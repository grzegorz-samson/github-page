Tak — przejrzałem to, co jest w Twoich paczkach (`frontend/src/...` i `backend/src/index.ts`) i mogę powiedzieć dwie rzeczy naraz:

1. **Publicznie “wiszących danych” po stronie backendu nie widzę** (o ile nie wycieknie token admina).
2. Masz **kilka realnych ryzyk**, które warto poprawić *zanim* wrzucisz to produkcyjnie na GitHub Pages (zwłaszcza przez `/admin`).

Poniżej konkret.

---

## 1) Czy po wypełnieniu formularza dane będą publiczne?

### Download / contact (public endpoints)

* Endpointy publiczne to: `/download`, `/contact`, `/analytics/pageview`, `/event`.
* **Nie ma endpointu typu “pokaż pobrania” bez autoryzacji.**
* Dane PII w `downloads` i `contact_messages` są w praktyce **szyfrowane** (AES-GCM; w bazie ląduje `enc:v2:...`). To jest OK.

### Admin endpoints (wrażliwe)

* Endpointy admin to: `/admin/stats`, `/admin/records`, `/admin/reencrypt`.
* Te endpointy zwracają **odszyfrowane PII** (np. imię/nazwisko/email) w `/admin/records?type=downloads`.
* Są chronione `ADMIN_API_TOKEN` → **jeśli token jest mocny i nie wycieknie, dane nie są publiczne**.

**Wniosek:** dane nie “wiszą publicznie”, ale bezpieczeństwo w 100% zależy od tego, czy nie wycieknie token admina / czy nie da się go wykraść.

---

## 2) Najważniejsze ryzyka w aktualnej wersji

### (A) Krytyczne: Stored-XSS na stronie `/admin` → kradzież tokenu

W `frontend/src/pages/admin.astro` renderujesz dane z backendu przez `innerHTML` (np. `recentEventsBody.innerHTML = ...`), wkładając do HTML wartości pochodzące z DB (`path`, `status` itd.).
A w backendzie pola eventów (`status`, `path`, `source`) **nie są oczyszczane z `< >`** (tylko `trim`/`slice`). Wystarczy, że ktoś wyśle event z `path="/</td><script>...</script>"` i gdy Ty wejdziesz w `/admin`, skrypt może się wykonać.

**Skutek:** token admina trzymasz w `sessionStorage` → XSS może go ukraść → potem atakujący może pobrać odszyfrowane dane przez `/admin/records`.

✅ **To jest rzecz #1 do poprawy przed produkcją.**

---

### (B) Krytyczne: dopuszczasz token admina w URL (`?token=...`)

W `isAdminAuthorized()` backend akceptuje token także jako query param:

```ts
const urlToken = new URL(request.url).searchParams.get('token')
```

To jest bardzo niebezpieczne, bo token może wyciec w logach, w historii przeglądarki, w referrerach, w screenshotach itd.

✅ **Usuń autoryzację przez query string.** Zostaw tylko `Authorization: Bearer ...`.

---

### (C) Średnie: `/admin` jest publiczną stroną na GitHub Pages

Nawet jeśli bez tokenu nic nie zobaczy, to:

* ułatwia to atak XSS/phishing,
* zwiększa “powierzchnię ataku”.

**Bez Cloudflare Access / custom domain** nie da się porządnie ukryć `/admin` na GitHub Pages.

✅ Jeśli jeszcze nie masz Cloudflare Access: **nie publikuj `/admin`** (trzymaj go lokalnie / w osobnym buildzie).

---

### (D) Drobniejsze: walidacja `path` w analytics/events jest zbyt luźna

`validatePageViewPayload()` i `validateEventPayload()` sprawdzają tylko `startsWith('/')`.
To wystarczy do działania, ale pozwala wrzucać znaki HTML i potem robi się problem po stronie admin UI.

✅ Po naprawie (A) to mniej groźne, ale i tak warto dodać whitelistę znaków dla `path`/`status` (np. bez `< >`).

---

### (E) Drobne: link do pobrania z backendu warto walidować

Frontend ustawia `href` z `result.downloadUrl`. Jeśli kiedyś ktoś źle ustawi `DOWNLOAD_URL` (np. `javascript:`), to masz XSS przez kliknięcie.

✅ W backendzie sprawdź, że `DOWNLOAD_URL` ma `https://` i sensowny host.

---

## 3) Czy to jest “wystarczająco bezpieczne”, by wrzucić na GitHub Pages?

### Tak, ale…

* **Strona publiczna (PL/EN, project, downloads, plugin, itd.)**: wygląda OK do publikacji.
* **NIE rekomenduję publikować `/admin` w tej formie** (ze względu na XSS + token w sessionStorage).

Jeśli chcesz dziś wypchnąć stronę na GH Pages, a admin mieć “dla siebie”:

* usuń `src/pages/admin.astro` z buildu **albo**
* przenieś admin panel do osobnego repo / osobnego builda, który uruchamiasz lokalnie.

---

## 4) Minimalny edit-script naprawczy (konkret)

### Fix 1 — usuń `innerHTML` w admin UI (najważniejsze)

**Plik:** `frontend/src/pages/admin.astro`
**Zmiany:**

* `node.innerHTML = ...` → buduj DOM przez `document.createElement()` i ustawiaj `textContent`.
* To samo dla tabeli `recentEventsBody` (twórz `<tr><td>...</td>...</tr>` przez DOM, nie string).

Efekt: nawet jeśli ktoś wstawi `<script>`, to zostanie pokazane jako tekst, nie wykona się.

### Fix 2 — nie zapisuj tokenu w `sessionStorage`

**Plik:** `frontend/src/pages/admin.astro`

* Usuń `sessionStorage.setItem(STORAGE_TOKEN, token)` i odczyt tokenu z sessionStorage.
* Token wpisujesz za każdym razem ręcznie (mniej wygodne, ale dużo bezpieczniejsze).

### Fix 3 — backend: usuń token w query param

**Plik:** `backend/src/index.ts` → funkcja `isAdminAuthorized()`

* Usuń blok:

```ts
const urlToken = new URL(request.url).searchParams.get('token')
```

### Fix 4 — backend: twardsza walidacja path/status

**Plik:** `backend/src/index.ts`

* Dodaj np. prosty filtr:

  * odrzuć jeśli zawiera `<` lub `>` w `path/status/source`
  * albo regex whitelist dla `path` (bez spacji i bez znaków HTML)

### Fix 5 — backend: walidacja `DOWNLOAD_URL`

* `new URL(downloadUrl)` i `url.protocol === 'https:'`

---

## 5) Szybki “checklist” przed publikacją

W repo front:

* brak `.env` w repo ✅ (u Ciebie wygląda OK)
* brak kluczy/API tokenów w kodzie ✅
* `/admin` niepublikowany albo zabezpieczony ✅ (u Ciebie na razie ❌)

W workerze:

* `ADMIN_API_TOKEN`, `DATA_ENCRYPTION_KEY`, `IP_HASH_SALT/DATA_HASH_PEPPER` jako **sekrety**, nie plaintext w plikach ✅
* brak tokenów w URL (po fixie) ✅

---

Jeśli chcesz, mogę teraz przygotować Ci **dokładny edit-script “patch”** (z gotowymi fragmentami kodu) dla:

* bezpiecznego renderowania admin tabel/wykresów bez `innerHTML`,
* usunięcia token query param,
* oraz lekkiej walidacji `path/status`.

Powiedz tylko: czy admin panel ma zostać jako `/admin` na tej samej domenie, czy tymczasowo wolisz go trzymać lokalnie (niepublikowany) aż do czasu ustawienia Cloudflare Access?
