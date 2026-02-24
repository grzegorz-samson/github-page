# Download Gate API (Cloudflare Worker + D1)

Backend for plugin download requests from the Astro website.

## 1) Install dependencies

```bash
cd backend/download-gate-api
npm install
```

## 2) Login to Cloudflare

```bash
npx wrangler login
```

## 3) Create D1 database

```bash
npm run d1:create
```

After creation:
- copy `database_id` into `wrangler.jsonc` (`REPLACE_WITH_D1_DATABASE_ID`),
- keep `binding` as `DB`.

## 4) Apply migration

```bash
npm run d1:migrate
```

## 5) Configure secrets

```bash
npx wrangler secret put DOWNLOAD_URL
npx wrangler secret put DOWNLOAD_SHA256
npx wrangler secret put ALLOWED_ORIGINS
npx wrangler secret put IP_HASH_SALT
```

`ALLOWED_ORIGINS` example:

```txt
https://your-user.github.io,https://your-custom-domain.com
```

## 6) Deploy

```bash
npm run deploy
```

## API

- `OPTIONS /download` (CORS preflight)
- `POST /download`
  - validates payload,
  - requires `consentTerms=true` and `consentUpdates=true`,
  - stores request in D1,
  - returns `{ downloadUrl, sha256 }`
- `GET /health`

## Notes

- This is a soft gate (cloud-drive link), not DRM.
- To use signed short-lived URLs, move binaries to storage that supports signed URLs (R2/S3/GCS).
