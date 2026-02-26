# Download Gate API (Cloudflare Worker + D1)

Backend for plugin download and contact flows used by the Astro website.

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
npx wrangler secret put DATA_ENCRYPTION_KEY
npx wrangler secret put DATA_HASH_PEPPER
npx wrangler secret put ADMIN_API_TOKEN
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put CONTACT_TO_EMAIL
npx wrangler secret put CONTACT_FROM_EMAIL
```

`ALLOWED_ORIGINS` example:

```txt
https://your-user.github.io,https://your-custom-domain.com
```

`DATA_ENCRYPTION_KEY`:
- use base64-encoded 32-byte key (AES-256-GCM),
- generate locally, for example:

```bash
python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
```

## 6) Deploy

```bash
npm run deploy
```

## Public API

- `OPTIONS /download` (CORS preflight)
- `POST /download`
  - validates payload,
  - stores request in D1,
  - returns `{ downloadUrl, sha256 }`
- `POST /contact`
  - validates payload,
  - stores request in D1,
  - tries Resend email notification
- `POST /analytics/pageview`
  - stores pageview event for internal analytics
- `POST /event`
  - stores download funnel events

## Admin API (token required)

- `GET /admin/stats`
- `GET /admin/records?type=downloads|contacts|pageviews|events`
- `POST /admin/reencrypt`
- `GET /health`

## Admin access

Pass admin token in one of:
- `Authorization: Bearer <ADMIN_API_TOKEN>` (recommended),
- `X-Admin-Token: <ADMIN_API_TOKEN>`.

Example:

```bash
curl -H "Authorization: Bearer <TOKEN>" "https://<worker>.workers.dev/admin/stats?days=30"
curl -H "Authorization: Bearer <TOKEN>" "https://<worker>.workers.dev/admin/records?type=downloads&limit=25"
curl -X POST -H "Authorization: Bearer <TOKEN>" "https://<worker>.workers.dev/admin/reencrypt"
```

## Security Notes (public-safe)

- This is a soft gate (cloud-drive link), not DRM.
- Secrets must be managed only in Cloudflare Secrets (never in git).
- Do not expose `ADMIN_API_TOKEN` outside private admin usage.
- For signed short-lived links, move binaries to storage with signed URLs (R2/S3/GCS).
