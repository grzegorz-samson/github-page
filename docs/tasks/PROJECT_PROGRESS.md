# Project Progress Tracker

Last update: 2026-02-26

## Goal
Build and publish a bilingual (PL/EN) scholarship project website documenting:
- VST plugin (images, documentation, download)
- Composition created with the plugin
- Research/conference materials

## Source Inputs Read
- `docs/tasks/Initial_plan.md`
- `docs/tasks/Initial_plan_project_draft.md`
- `docs/tasks/Initial_plan_project_edit_script_v1.md`
- `docs/context/kontekst wniosek.pdf`
- `docs/context/research/*` (poster + source doc)
- `docs/context/bio/*` (portfolio, CV, profile photo, materials)
- `docs/context/plugin/*` (overview, features, GUI architecture, panel assets)
- `docs/context/workshops/*` (workshop agenda and poster)
- `docs/context/certificates/*` (training certificates: MATLAB, Dataiku, AWS)
- `docs/context/scholarship trademarks/*` (KPO branding)

## Changelog
### 2026-02-26
- Added detailed implementation documentation:
  - `docs/tasks/SECURITY_SITE_IMPLEMENTATION_2026-02-26.md`
- Confirmed primary production site is now:
  - `https://grzegorz-samson.github.io/`
- Legacy GitHub Pages site for repo `github-page` was disabled.
- Implemented backend security upgrade locally (not published yet):
  - encrypted-at-rest form fields in Worker/D1 flow,
  - hashed identifiers for analytics/dedup (`email_hash`, `ip_hash`),
  - admin-only stats and records endpoints.
- Added D1 migration for secure storage and pageview analytics:
  - `backend/download-gate-api/migrations/0004_secure_storage_and_pageviews.sql`
- Added pageview tracker on frontend:
  - `src/components/PageViewTracker.astro`
- Added local image performance optimization (not published yet):
  - workshop thumbnails (`.webp`) and profile thumbnail (`.webp`) with full-res click-through.
- Updated favicon asset locally (centered `GS`, not published yet).

### 2026-02-24
- Added public research assets:
  - `public/assets/research/from-text-wishes-to-sound-adc-2025-poster.jpg`
  - `public/assets/research/from-text-wishes-to-sound-adc-2025-poster.docx`
- Added public KPO branding assets:
  - `public/assets/funding/kpo-rp-ngeu-color.png`
  - `public/assets/funding/kpo-ngeu-achromatic.png`
- Added public bio assets:
  - `public/assets/bio/grzegorz-samson-profile.png`
  - `public/assets/bio/portfolio-grzegorz-samson-pl.pdf`
  - `public/assets/bio/grzegorz-samson-cv-en-2025.pdf`
- Implemented `src/components/FundingFooter.astro` with finalized funding note text.
- Updated PL content across pages (`/pl/index`, `/pl/project`, `/pl/downloads`, `/pl/updates`, `/pl/bio`) with Polish diacritics.
- Reworked `/pl/project#research`: poster summary, ADC 2025 metadata, poster/docx links, poster preview.
- Reworked `/pl/bio` using context materials: profile photo, biogram, selected publications, conferences, portfolio and CV links.
- Added supporting styles for funding footer alignment, poster card, and bio layout.
- Reworked `/pl/bio` publications section into separated article cards with dedicated links under each item.
- Added interactive timeline (expand/collapse) for “Wybrane wystąpienia i aktywności” in `/pl/bio`.
- Added AES article direct link in publications:
  - `https://aes.org/publications/elibrary-page/?id=22884`
- Updated publication link labels: DOI entries now display clickable DOI numbers instead of the generic label.
- Replaced bio activity list with a horizontal interactive timeline (rail + active detail card).
- Removed visible top/bottom gradient strips by simplifying global background and removing edge-revealing margins.
- Timeline refinement: years are now anchored to the axis with subtle vertical separators at the start of each year group.
- Timeline separators are visual-only (short, low-contrast), keeping card readability and preserving mobile horizontal scrolling.
- Updated `/pl/bio`: short intro on top + full note section at the bottom with clearer paragraph spacing and highlighted links.
- Updated full bio note so the KPO project link is embedded directly in the project title.
- Removed public portfolio/CV exposure:
  - removed buttons from `/pl/bio`
  - removed `public/assets/bio/portfolio-grzegorz-samson-pl.pdf`
  - removed `public/assets/bio/grzegorz-samson-cv-en-2025.pdf`
- Navigation update (PL): replaced `Pobieranie` with `Wtyczka VST` and added new tabs:
  - `Nauka`
  - `Warsztaty`
  - `Stypendium`
- Reworked `/pl/downloads` into a full `Wtyczka VST` page with plugin functionality, use-cases, and panel descriptions.
- Added public plugin panel assets:
  - `public/assets/plugin/controls-panel.png`
  - `public/assets/plugin/multichannel-panel.png`
  - `public/assets/plugin/audio-generator-panel.png`
- Added new science page with ADC 2025 materials:
  - `src/pages/pl/science.astro`
- Added new workshops page based on workshop context:
  - `src/pages/pl/workshops.astro`
  - `public/assets/workshops/warsztaty-27-02-2026-gs.png`
- Added new scholarship page with milestones and training certificates:
  - `src/pages/pl/scholarship.astro`
  - `public/assets/certificates/certyfikat-kurs-1-matlab.pdf`
  - `public/assets/certificates/certyfikat-kurs-2-dataiku.pdf`
  - `public/assets/certificates/certyfikat-kurs-3-aws.pdf`
- Updated scholarship milestone labels to `zrealizowane` and set all milestone statuses to `done`.
- Added download-gate frontend integration:
  - `src/components/DownloadGateModal.astro`
  - `src/lib/config.ts`
  - `src/lib/downloadGate.ts`
  - integrated on `/pl/downloads` (`/pl/plugin`) and `/en/downloads` (`/en/plugin`)
- Added legal pages for download consent:
  - `src/pages/pl/regulamin.mdx`
  - `src/pages/en/terms.mdx`
- Added Cloudflare Worker backend scaffold with D1 migration:
  - `backend/download-gate-api/src/index.ts`
  - `backend/download-gate-api/migrations/0001_init.sql`
  - `backend/download-gate-api/wrangler.jsonc`
  - `backend/download-gate-api/README.md`

## Scholarship Tasks (from context PDF)
1. Courses and training (09.2025-10.2025)  
Status: done (reflected in project timeline and narrative).
2. International conference presentation (10.2025-11.2025)  
Status: done (research section now includes conference-linked materials).
3. VST plugin concept and implementation (10.2025-12.2025)  
Status: done (reflected in project and scholarship milestone sections).
4. Composition using generative tools (12.2025-01.2026)  
Status: done (marked as completed in scholarship milestone sections).
5. Open workshops and lectures (12.2025-02.2026)  
Status: done (workshop page and materials added).
6. Documentation and distribution (01.2026-02.2026)  
Status: done (milestones marked as completed; release publication still maintained as staged in VST tab).

## Website Implementation Tasks
- [x] Initialize Astro project with Tailwind and MDX.
- [x] Add PL/EN route structure (`/pl/*`, `/en/*`).
- [x] Build shared layout + language switch.
- [x] Implement main project landing page in PL and EN.
- [x] Implement supporting pages: home, downloads, updates, bio.
- [x] Implement PL funding footer with KPO branding and final note.
- [x] Publish research poster assets and add research section links.
- [x] Publish bio assets and update PL bio page from source materials.
- [ ] Add final binary download links and checksums for public release.
- [ ] Add full conference evidence set (abstract/slides/program/video links).
- [x] Add workshop section details and evidence materials.
- [ ] Configure final deployment URL/domain and production CI settings.

## Notes / Next Focus
- PL copy is now normalized with Polish diacritics and consistent terminology.
- In the dark theme, funding footer now targets monochromatic KPO presentation.
- `docs/context/bio/Materials for bio.txt` is now populated and included in the bio content update.

## Security Hardening (2026-02-26)
- Implemented admin UI XSS hardening in `src/pages/admin.astro`:
  - removed HTML string rendering (`innerHTML`) for charts/tables,
  - switched to DOM node creation + `textContent`,
  - stopped persisting admin token in browser storage.
- Implemented backend auth hardening in `backend/download-gate-api/src/index.ts`:
  - removed admin token transport via URL query (`?token=`),
  - kept header-based auth (`Authorization: Bearer`, `X-Admin-Token`).
- Tightened payload validation in `backend/download-gate-api/src/index.ts`:
  - added unsafe character guard for analytics/event fields (`<`, `>`, `|`, control chars),
  - validation now rejects unsafe `path`, `status`, and `source`.
- Added strict download URL validation in `backend/download-gate-api/src/index.ts`:
  - download link must parse as URL and use `https:` protocol.
- Updated docs:
  - `backend/download-gate-api/README.md`
  - `docs/tasks/SECURITY_SITE_IMPLEMENTATION_2026-02-26.md`
