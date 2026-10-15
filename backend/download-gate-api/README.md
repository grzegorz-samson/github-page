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
npx wrangler secret put TURNSTILE_SECRET_KEY
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
  - verifies `turnstileToken` server-side (hostname must match allowed Origin, action must be `contact`),
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

## Contact form on grzegorz-samson.github.io

The current limited test configuration uses a separate Resend account registered
to `grzegorzsamson218@hotmail.com` and the sender `onboarding@resend.dev`.
It can send only to that account's email. A verified owned domain is required
before changing recipients or using Resend for general delivery.

1. In Resend, verify a domain you control and choose a sender on that domain.
   `CONTACT_TO_EMAIL` must be `grzegorzsamson218@hotmail.com`.
   `CONTACT_FROM_EMAIL` is the verified sender, **not** the visitor's address.
   Replies use the visitor's email through `reply_to`.
   `onboarding@resend.dev` is only suitable for testing to the email registered with Resend.
2. Create a managed Cloudflare Turnstile widget for `grzegorz-samson.github.io`.
   Use a separate development widget for `localhost` / `127.0.0.1` if needed.
   Store its secret as `TURNSTILE_SECRET_KEY` in this same Worker.
3. Set the other Worker secrets above, including `RESEND_API_KEY`, and ensure
   `ALLOWED_ORIGINS` includes `https://grzegorz-samson.github.io`.
   Keep existing encryption, database, download and analytics configuration.
4. The source GitHub workflow includes public defaults; optional Actions variable overrides are:
   - `PUBLIC_API_BASE`: `https://download-gate-api.s20796-download-gate.workers.dev`
   - `PUBLIC_TURNSTILE_SITE_KEY`: the public sitekey (never the secret).
   Local builds read the same variable names from the ignored `.env`.
5. Deploy Worker and rebuild/publish the site together. The new Worker rejects
   older clients without a CAPTCHA token; avoid leaving only one half deployed.
6. Test both `/en/bio/` and `/pl/bio/`: invalid/expired CAPTCHA must not send mail;
   a valid submission must appear in Resend and arrive in the recipient inbox.
   An accepted Resend API request does not prove inbox delivery. Check spam too.

Missing server credentials return 503 before sending/storing a new contact.
When Resend fails after verification, the message is still stored encrypted in D1
and the UI explicitly reports that email delivery was unavailable. There is no automatic retry queue.

References: [Resend sender restrictions](https://resend.com/docs/knowledge-base/403-error-resend-dev-domain),
[Turnstile server validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).
