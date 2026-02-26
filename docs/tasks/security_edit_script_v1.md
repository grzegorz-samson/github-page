Tak — da się to zrobić sensownie, ale warto rozdzielić dwie rzeczy:

1. **PII (imię, nazwisko, e-mail, „inne” itp.)** → szyfrujesz aplikacyjnie przed zapisem do bazy (żeby w D1 nie było plaintextu).
2. **Statystyki ruchu / wejścia / konwersje / pobrania** → najlepiej zbierać **bez PII** (agregaty i/lub hashe), bo to upraszcza RODO i bezpieczeństwo.

Poniżej masz konkretny plan wdrożenia + edit-script.

---

## A. Szyfrowanie danych w D1 tak, żebyś mógł je odczytać

### Co rekomenduję (praktycznie)

* Szyfruj **cały „payload PII”** jako JSON (imię, nazwisko, email, cele, inne) przy pomocy **AES-256-GCM** w Workerze (Web Crypto API jest dostępne w Cloudflare Workers). ([Cloudflare Docs][1])
* Klucz główny trzymasz jako **Worker Secret** (tylko Ty masz dostęp).
* W bazie trzymasz:

  * `pii_ciphertext_b64`, `pii_iv_b64` (i ew. `pii_aad_b64`)
  * oraz **minimalne metadane** do działania systemu: `created_at`, `plugin_version`, `lang`, flagi zgód (nie są PII), plus ewentualnie `email_hash` (do wyszukiwania bez deszyfrowania).
* **Nie zapisuj surowego IP**. Jeśli koniecznie chcesz „unikalnych” i anty-spam, zapisuj `ip_hash = sha256(ip + pepper)` (pepper jako secret). To nadal dane osobowe w sensie RODO, ale dużo bezpieczniejsze niż IP.

### Dlaczego nie „wszystko zaszyfrowane łącznie z metadanymi”?

Można, ale potem nie da się robić niczego sensownego bez masowego deszyfrowania rekordów. Lepiej: PII w ciphertext, a statystyka jako osobny strumień zdarzeń bez PII.

---

## B. Statystyki strony tylko dla Ciebie (admin-only)

Masz dwa poziomy:

### 1) Statystyki „WWW” (pageviews/visits) — bez pisania własnej analityki

**Cloudflare Web Analytics**: prywatnościowe, lekkie, “for free” i widoczne tylko w Twoim panelu Cloudflare. ([cloudflare.com][2])
To daje Ci wejścia, popularne strony, referrery, itd. Zwykle **bez potrzeby zbierania IP** samemu.

### 2) Statystyki „produktowe” (lejek pobierania)

Do tego najlepsze jest **Workers Analytics Engine**:

* zapisujesz zdarzenia z Workera (`page_view`, `download_modal_open`, `download_form_submit_ok`, `download_link_shown`, itp.)
* potem je liczysz SQL-em (agregaty) ([Cloudflare Docs][3])
  Uwaga: domyślna retencja danych w Analytics Engine to **3 miesiące**. ([Cloudflare Docs][4])
  Jeśli chcesz dłużej, zrzucaj dzienne agregaty do D1.

---

# EDIT-SCRIPT: szyfrowane pobrania + admin stats

## Phase 1 — Backend: Crypto helpers + schema D1

### 1.1 DB: nowa tabela `downloads`

**Create migration** `migrations/001_downloads.sql`:

```sql
CREATE TABLE IF NOT EXISTS downloads (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  lang TEXT,
  plugin_version TEXT,

  consent_terms INTEGER NOT NULL,
  consent_stats INTEGER NOT NULL,
  consent_updates INTEGER NOT NULL,

  email_hash TEXT,         -- sha256(normalized_email + pepper) (opcjonalnie)
  ip_hash TEXT,            -- sha256(ip + pepper) (opcjonalnie)

  pii_iv_b64 TEXT NOT NULL,
  pii_ct_b64 TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_downloads_created_at ON downloads(created_at);
CREATE INDEX IF NOT EXISTS idx_downloads_email_hash ON downloads(email_hash);
```

### 1.2 Worker secrets

Ustaw sekrety (przykład):

* `PII_MASTER_KEY_B64` (32 bajty base64)
* `HASH_PEPPER` (losowy string)

Klucz AES-256: 32 bajty. W Workerze importujesz jako `crypto.subtle.importKey`.

### 1.3 Crypto: `src/crypto.ts` (w Workerze)

* `importAesKey(masterKeyB64)`
* `encryptJson(key, payload) -> { ivB64, ctB64 }`
* `decryptJson(key, ivB64, ctB64) -> payload`

Użyj **Web Crypto API** w Workerze (AES-GCM). ([Cloudflare Docs][1])

**Ważne praktyczne zasady:**

* IV: 12 bajtów losowo (`crypto.getRandomValues`)
* AAD: opcjonalnie `download-id` lub `created_at` (wtedy trudniej podmienić rekordy)
* Utrata klucza = utrata możliwości odczytu danych (zrób offline backup klucza).

### 1.4 Hash helper

* `normalizeEmail = lower(trim(email))`
* `email_hash = sha256(normalizeEmail + HASH_PEPPER)`
* `ip_hash = sha256(ip + HASH_PEPPER)` (tylko jeśli potrzebujesz)

---

## Phase 2 — Endpointy: /download + admin decrypt export

### 2.1 `POST /download`

1. Walidacja pól z formularza (terms required)
2. Zbuduj `piiPayload`:

```json
{
  "firstName": "...",
  "lastName": "...",
  "email": "...",
  "purposes": ["student","badacz", "..."],
  "purposeOther": "..."
}
```

3. Zaszyfruj `piiPayload` → `ivB64`, `ctB64`
4. Zapisz w D1: metadane + ciphertext
5. Zwróć:

```json
{
  "downloadUrl": "...", 
  "sha256": "...",
  "expiresAt": "..." // jeśli kiedyś dodasz signed URL
}
```

### 2.2 `GET /admin/downloads?from=&to=&limit=&cursor=`

* Zabezpieczenie:

  * najlepiej Cloudflare Access (Zero Trust) **albo**
  * Bearer token w nagłówku (secret)
* Pobierz rekordy z D1
* Zdeszyfruj `piiPayload` i zwróć JSON (albo CSV do pobrania)

**Uwaga**: to endpoint “wysokiego ryzyka” — zabezpieczaj mocno.

---

## Phase 3 — Analytics (Twoje prywatne statystyki)

### 3.1 Workers Analytics Engine dataset

Dodaj binding w `wrangler.toml/jsonc` Worker’a (zgodnie z “Get started”). ([Cloudflare Docs][3])
W Workerze zapisuj zdarzenia przez `writeDataPoint()` (pola w stałej kolejności, tylko jeden index). ([Cloudflare Docs][3])

**Proponowane zdarzenia (bez PII):**

* `page_view` (path, lang)
* `download_modal_open`
* `download_submit_ok`
* `download_link_shown`
* `download_clicked`
* `download_submit_error` (kod błędu)

**Dane (bez IP):**

* `path`, `lang`, `plugin_version`
* kraj/miasto z `request.cf` (geolokacja jest w request context) – jeśli chcesz (nadal uważaj w polityce prywatności)

### 3.2 `POST /event`

Frontend wywołuje `/event` na page load i przy akcjach modala:

* `sendBeacon` albo `fetch` (z `keepalive: true`)
  Worker zapisuje data point do Analytics Engine.

### 3.3 `GET /admin/stats`

* Zabezpiecz jak admin endpoint
* Worker wykonuje query do SQL API Analytics Engine i zwraca agregaty (np. last 7/30 dni).
  Cloudflare opisuje query przez SQL API i przykładowe zapytania. ([Cloudflare Docs][3])
  Pamiętaj o retencji ~3 miesiące (jeśli chcesz dłużej, zapisuj dzienne sumy do D1). ([Cloudflare Docs][4])

### 3.4 (Opcjonalnie) Cloudflare Web Analytics dla ogólnego ruchu WWW

Włącz Web Analytics w Cloudflare i dodaj snippet na stronę — dashboard dostępny tylko dla Ciebie. ([cloudflare.com][2])

---

## Phase 4 — Frontend: modal + po sukcesie link+SHA

### 4.1 Update `DownloadGateModal`:

* Submit → `POST /download`
* Success state → pokazuje `downloadUrl` + `sha256`
* Dodatkowo: wyślij eventy do `/event` (open, submit_ok, etc.)

### 4.2 Podstrona regulamin/RODO

* Uzupełnij: cele przetwarzania + podstawy prawne + czas przechowywania + cofnięcie zgody
* W treści wyraźnie: **IP nie jest przechowywane wprost** (jeśli tak zdecydujesz)

---

# Minimalny “security checklist”

* ✅ AES-GCM w Workerze (Web Crypto) ([Cloudflare Docs][1])
* ✅ Klucze tylko w Worker Secrets
* ✅ Admin endpointy za Cloudflare Access / Bearer
* ✅ Brak raw IP (hash tylko jeśli konieczne)
* ✅ Analytics bez PII (Workers Analytics Engine) ([Cloudflare Docs][5])

---

## Co potrzebuję od Ciebie, żeby dopiąć implementację w kodzie (bez kolejnych pytań „blokujących”)

Nie musisz odpowiadać teraz, ale od tego zależą szczegóły:

1. Czy backend ma być **Cloudflare Worker + D1** (tak jak tu), czy inny dostawca?
2. Czy chcesz “admin panel” jako **stronę /admin** (UI), czy wystarczy endpoint **/admin/downloads** do eksportu?

Jeśli potwierdzisz **Worker + D1**, to w następnym kroku mogę wkleić gotowe pliki Worker’a (TypeScript): `crypto.ts`, `hash.ts`, `routes/download.ts`, `routes/admin.ts`, `routes/event.ts` + przykładowe SQL do statystyk (7/30 dni) pod Analytics Engine.

[1]: https://developers.cloudflare.com/workers/runtime-apis/web-crypto/?utm_source=chatgpt.com "Web Crypto · Cloudflare Workers docs"
[2]: https://www.cloudflare.com/web-analytics/?utm_source=chatgpt.com "Cloudflare Web Analytics"
[3]: https://developers.cloudflare.com/analytics/analytics-engine/get-started/ "Get started with Workers Analytics Engine · Cloudflare Analytics docs"
[4]: https://developers.cloudflare.com/analytics/analytics-engine/limits/?utm_source=chatgpt.com "Workers Analytics Engine — Limits"
[5]: https://developers.cloudflare.com/analytics/analytics-engine/?utm_source=chatgpt.com "Workers Analytics Engine"
