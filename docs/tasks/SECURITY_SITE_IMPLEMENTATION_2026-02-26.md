# Security and Site Implementation Status (2026-02-26)

## Scope
This document summarizes the current implementation of:
- website structure and deployment,
- download/contact backend security model,
- analytics for admin-only usage,
- local changes waiting for publish.

## Site Architecture
- Frontend: Astro static site (`/pl/*`, `/en/*`).
- Primary production URL: `https://grzegorz-samson.github.io/`.
- Legacy Pages site from `github-page` repo has been disabled.
- Language switch works between PL/EN route equivalents.
- Shared layout: `src/layouts/PageLayout.astro`.

## Current Frontend Security-Relevant Behavior
- Download flow uses API calls to Worker (`PUBLIC_API_BASE`).
- Contact form uses API calls to Worker (`PUBLIC_API_BASE`).
- Obfuscated email rendering component is used to reduce simple scraper harvesting:
  - `src/components/ObfuscatedEmailImage.astro`.
- Legal consent links in download modal point to terms/license/privacy pages.

## Backend Security Model (Worker + D1)
Backend path: `backend/download-gate-api`.

### Data-at-rest approach
- Sensitive form fields are stored encrypted (AES-GCM) in D1.
- Deterministic matching fields use HMAC-SHA256 hashes (pepper-based), e.g. `email_hash`.
- IP is stored as hash (`ip_hash`), not raw IP.
- Encryption format in DB: `enc:v1:<base64iv>.<base64cipher>`.

### Endpoints
- Public:
  - `POST /download`
  - `POST /contact`
  - `POST /analytics/pageview`
  - `POST /event` (download funnel events)
  - `OPTIONS` for CORS preflight
  - `GET /health`
- Admin-only (token required):
  - `GET /admin/stats`
- `GET /admin/records?type=downloads|contacts|pageviews|events`
  - `POST /admin/reencrypt` (one-time helper to encrypt legacy plaintext records)

### Admin auth
Accepted token transport (first available):
- `Authorization: Bearer <ADMIN_API_TOKEN>`
- `X-Admin-Token: <ADMIN_API_TOKEN>`

### Abuse controls
- CORS allowlist via `ALLOWED_ORIGINS`.
- Honeypot fields in download/contact/pageview payloads.
- Rate limiting by `ip_hash` in a rolling window.

## D1 Schema Updates
Migration added:
- `backend/download-gate-api/migrations/0004_secure_storage_and_pageviews.sql`

Includes:
- `email_hash` columns in request tables,
- `pageviews` table with indexes for analytics.

## Analytics (Admin-Only)
- Frontend tracker: `src/components/PageViewTracker.astro`.
- Tracker sends pageview events to Worker.
- Download modal sends funnel events to `/event` (`download_modal_open`, `download_submit_ok`, `download_submit_error`, `download_link_shown`, `download_clicked`).
- Aggregated stats available only via admin endpoints.
- Raw analytics data exposed to admin is hash-based where applicable (`ip_hash`, `user_agent_hash`).

## Deployment and Secrets
Worker secrets required:
- `DOWNLOAD_URL`
- `DOWNLOAD_SHA256`
- `ALLOWED_ORIGINS`
- `IP_HASH_SALT`
- `DATA_ENCRYPTION_KEY` (base64, 16/24/32-byte raw key; recommended 32-byte)
- `DATA_HASH_PEPPER`
- `ADMIN_API_TOKEN`
- `RESEND_API_KEY`
- `CONTACT_TO_EMAIL`
- `CONTACT_FROM_EMAIL`

## Local-Only Changes Pending Publish
The following changes are currently local and not published yet:
- optimized workshop thumbnails (`.webp`) + click-through to full-resolution images,
- optimized profile image thumbnail (`.webp`) + click-through to full-resolution image,
- updated and centered favicon (`GS`).

## Operational Notes
- If legacy rows exist in plaintext, run:
  - `POST /admin/reencrypt` once after deploying the new worker build.
- Keep `ADMIN_API_TOKEN`, `DATA_ENCRYPTION_KEY`, and `DATA_HASH_PEPPER` rotated and stored only in secrets manager.
