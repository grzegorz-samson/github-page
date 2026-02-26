Pewnie — poniżej masz **konkretny edit-script “security patch”** dla Twojego obecnego frontu i backendu. Skupiam się na najważniejszych realnych ryzykach, które u Ciebie występują teraz:

* **XSS w `/admin`** (wynika z użycia `innerHTML` do renderowania danych z backendu)
* **token admina w URL** (`?token=...`) w backendzie
* **luźna walidacja pól eventów** (pozwala wstrzyknąć HTML/znaki rozdzielające)
* **walidacja `DOWNLOAD_URL`** (żeby nie dało się przypadkiem zwrócić `javascript:`)

---

# EDIT-SCRIPT: Security Patch (Frontend + Backend)

## Zasady

* Po każdej fazie: `git status` → commit.
* Nie zmieniaj logiki funkcjonalnej (pobrania/stats), tylko **utwardź bezpieczeństwo**.

---

## PHASE 1 — FRONTEND: usunięcie `innerHTML` w `/admin` (XSS fix)

### 1.1 Plik: `frontend/src/pages/admin.astro`

**Cel:** nigdy nie renderować danych z API przez `innerHTML`. Wszystko przez DOM + `textContent`.

#### 1) Zaktualizuj opis w panelu (opcjonalnie)

W treści w `<p>` zmień fragment o sessionStorage na coś w stylu:

* “Token jest wpisywany ręcznie i nie jest przechowywany.”

(To będzie spójne z następną zmianą.)

#### 2) W `<script type="module">` usuń zapisywanie tokenu do `sessionStorage`

**Znajdź:**

```js
const STORAGE_TOKEN = 'adminApiToken';
```

**Zamień na:**

```js
// Token intentionally NOT persisted (prevents token theft persistence on XSS)
```

(albo usuń w ogóle stałą; ważne, żeby dalej nic nie używało STORAGE_TOKEN)

**Znajdź w `fetchAdmin`:**

```js
sessionStorage.setItem(STORAGE_API, base);
sessionStorage.setItem(STORAGE_TOKEN, token);
```

**Zamień na:**

```js
sessionStorage.setItem(STORAGE_API, base);
// do NOT persist token
```

**Znajdź inicjalizację tokenu na końcu:**

```js
if (tokenInput instanceof HTMLInputElement) {
  const savedToken = sessionStorage.getItem(STORAGE_TOKEN);
  if (savedToken) tokenInput.value = savedToken;
}
```

**Usuń cały blok.**

#### 3) Zastąp renderowanie HTML (bar charts, top lists, tabelka eventów) DOM-builderem

W `admin.astro` masz teraz funkcje:

* `createBarItem()` → zwraca string HTML
* `renderSeries()` → `node.innerHTML = ...`
* `renderTopList()` → `node.innerHTML = ...`
* `renderRecentEvents()` → `recentEventsBody.innerHTML = ...`

Zastąp je wersją “bezpieczną”.

**Wklej i podmień cały blok od `const createBarItem = ...` do końca `renderRecentEvents`:**

```js
const clearNode = (node) => {
  while (node.firstChild) node.removeChild(node.firstChild);
};

const appendEmptyItem = (node, text) => {
  const li = document.createElement('li');
  li.className = 'admin-empty-item';
  li.textContent = text;
  node.appendChild(li);
};

const createBarItemEl = (label, total, maxTotal) => {
  const width = maxTotal > 0 ? Math.max(4, (total / maxTotal) * 100) : 0;

  const li = document.createElement('li');
  li.className = 'admin-bar-item';

  const labelSpan = document.createElement('span');
  labelSpan.className = 'admin-bar-label';
  labelSpan.textContent = label;

  const track = document.createElement('div');
  track.className = 'admin-bar-track';

  const fill = document.createElement('span');
  fill.className = 'admin-bar-fill';
  fill.style.width = `${width}%`;

  const valueSpan = document.createElement('span');
  valueSpan.className = 'admin-bar-value';
  valueSpan.textContent = String(total);

  track.appendChild(fill);
  li.appendChild(labelSpan);
  li.appendChild(track);
  li.appendChild(valueSpan);
  return li;
};

const renderSeries = (node, items, labelKey = 'day') => {
  if (!(node instanceof HTMLElement)) return;
  clearNode(node);

  if (!Array.isArray(items) || items.length === 0) {
    appendEmptyItem(node, 'Brak danych');
    return;
  }

  const maxTotal = items.reduce((max, item) => Math.max(max, Number(item?.total ?? 0)), 0);
  for (const item of items) {
    const label = String(item?.[labelKey] ?? '-');
    const total = Number(item?.total ?? 0);
    node.appendChild(createBarItemEl(label, total, maxTotal));
  }
};

const renderTopList = (node, items, labelKey) => {
  if (!(node instanceof HTMLElement)) return;
  clearNode(node);

  if (!Array.isArray(items) || items.length === 0) {
    appendEmptyItem(node, 'Brak danych');
    return;
  }

  const sliced = items.slice(0, 12);
  const maxTotal = sliced.reduce((max, item) => Math.max(max, Number(item?.total ?? 0)), 0);

  for (const item of sliced) {
    const label = String(item?.[labelKey] ?? '-');
    const total = Number(item?.total ?? 0);
    node.appendChild(createBarItemEl(label, total, maxTotal));
  }
};

const renderRecentEvents = (items) => {
  if (!(recentEventsWrap instanceof HTMLElement) || !(recentEventsBody instanceof HTMLElement)) return;
  recentEventsWrap.hidden = false;
  clearNode(recentEventsBody);

  if (!Array.isArray(items) || items.length === 0) {
    if (recentEventsEmpty instanceof HTMLElement) recentEventsEmpty.hidden = false;
    return;
  }
  if (recentEventsEmpty instanceof HTMLElement) recentEventsEmpty.hidden = true;

  for (const row of items.slice(0, 30)) {
    const tr = document.createElement('tr');

    const tdTime = document.createElement('td');
    tdTime.textContent = String(row?.createdAt ?? '-');

    const tdEvent = document.createElement('td');
    tdEvent.textContent = String(row?.event ?? '-');

    const tdStatus = document.createElement('td');
    tdStatus.textContent = String(row?.status ?? '-');

    const tdPath = document.createElement('td');
    tdPath.textContent = String(row?.path ?? '-');

    tr.appendChild(tdTime);
    tr.appendChild(tdEvent);
    tr.appendChild(tdStatus);
    tr.appendChild(tdPath);
    recentEventsBody.appendChild(tr);
  }
};
```

✅ To usuwa wektor XSS z `/admin` nawet jeśli backend zwróci “złośliwe” stringi.

---

## PHASE 2 — BACKEND: usuń token w URL (critical) + ogranicz payload eventów

### 2.1 Plik: `backend/src/index.ts` — usuń autoryzację przez query param

**Znajdź w `isAdminAuthorized`:**

```ts
const urlToken = new URL(request.url).searchParams.get('token')?.trim() ?? '';
if (urlToken) {
  return timingSafeEqual(urlToken, token);
}
```

**Usuń ten blok w całości.**

Zostaw tylko:

* `Authorization: Bearer ...`
* ewentualnie `X-Admin-Token` (jeśli chcesz; najlepiej trzymać się Bearer)

---

### 2.2 Plik: `backend/src/index.ts` — dodaj walidację “anty-HTML” dla eventów/pageviews

Dodaj helpery (np. zaraz po `normalizeText`):

```ts
function hasUnsafeChars(value: string): boolean {
  // blokuje proste XSS i rozbijanie pól w referrerze (|)
  return /[<>]/.test(value) || value.includes('|') || /[\u0000-\u001f\u007f]/.test(value);
}
```

#### Zmodyfikuj `validatePageViewPayload`:

**Dodaj po sprawdzeniu `startsWith('/')`:**

```ts
if (hasUnsafeChars(payload.path)) return 'Invalid path.';
```

#### Zmodyfikuj `validateEventPayload`:

**Dodaj:**

```ts
if (hasUnsafeChars(payload.path)) return 'Invalid path.';
if (payload.status && hasUnsafeChars(payload.status)) return 'Invalid status.';
if (payload.source && hasUnsafeChars(payload.source)) return 'Invalid source.';
```

✅ To minimalizuje ryzyko “wstrzyknięcia” w Twoje logi i admin UI.

---

### 2.3 Plik: `backend/src/index.ts` — waliduj `DOWNLOAD_URL` jako https URL

W `handleDownload` masz:

```ts
const downloadUrl = env.DOWNLOAD_URL.trim();
if (!downloadUrl || downloadUrl.includes('DOWNLOAD_URL_PLACEHOLDER') || downloadUrl.startsWith('<')) {
  ...
}
```

**Rozszerz to o:**

```ts
let parsedUrl: URL | null = null;
try {
  parsedUrl = new URL(downloadUrl);
} catch {
  parsedUrl = null;
}

if (!parsedUrl || parsedUrl.protocol !== 'https:') {
  return jsonResponse(
    { error: 'download_config_invalid', message: 'Download URL must be a valid https URL.' },
    500,
    origin,
    env
  );
}
```

✅ Chroni przed przypadkowym `javascript:` lub źle sformatowanym linkiem.

---

## PHASE 3 — (Opcjonalnie, ale polecam) Usuń `/admin` z publicznego buildu dopóki nie masz Cloudflare Access

Jeśli jeszcze nie masz Cloudflare Access:

* `/admin` jest publicznie dostępne jako strona (choć po fixach nie wyciekną dane bez tokenu)
* ale nadal jest to “powierzchnia ataku” i może kusić.

**Szybka opcja “bezpieczna”:**

* przenieś `src/pages/admin.astro` do np. `src/pages/_admin_disabled.astro`
* albo dodaj w `admin.astro` na górze czytelny “kill switch”:

Wstaw na początku `<PageLayout ...>`:

```astro
{import.meta.env.PROD ? (
  <p class="text-panel">Admin disabled in production build.</p>
) : null}
```

Docelowo: ochraniasz `/admin*` przez Cloudflare Access (najlepsze).

---

## PHASE 4 — Manual QA (5 minut)

1. Wejdź w `/admin` i sprawdź:

   * wykresy renderują się poprawnie
   * tabelka eventów działa
2. Spróbuj wysłać event z `<script>` w `path`:

   * backend powinien zwrócić `400 validation_error`
3. Spróbuj użyć tokenu w URL: `/admin/stats?token=...`:

   * powinno zwrócić `401`
4. Kliknij “Pobierz statystyki” i sprawdź brak błędów.

---

# Co to Ci daje (wprost)

* **Nie będzie XSS w admin panelu** przez dane z DB (największy problem).
* **Token nie wycieknie w URL** (duża różnica bezpieczeństwa).
* **Eventy/pageviews nie wstrzykną HTML** ani delimiterów do Twoich logów.
* Możesz bezpieczniej wrzucić stronę na GitHub Pages (publiczną część).

---

Jeśli chcesz, mogę też dorzucić **mini-hardening**:

* nagłówek `Referrer-Policy: no-referrer` (tam gdzie możesz),
* ograniczenie CORS na admin endpointach (tylko Twoja domena),
* opcjonalny CSP (ale na Astro + inline script w `/admin` trzeba to zrobić ostrożnie).

Powiedz tylko, czy `/admin` chcesz **zostawić w produkcji** po wdrożeniu Cloudflare Access, czy wolisz docelowo osobny “admin build”.
