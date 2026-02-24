interface Env {
  DB: D1Database;
  DOWNLOAD_URL: string;
  DOWNLOAD_SHA256: string;
  ALLOWED_ORIGINS: string;
  IP_HASH_SALT: string;
}

interface DownloadPayload {
  firstName: string;
  lastName: string;
  email: string;
  purposes: string[];
  purposeOther: string;
  institution: string;
  consentTerms: boolean;
  consentStats: boolean;
  consentUpdates: boolean;
  lang: string;
  pluginVersion: string;
  website: string;
}

const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PURPOSE_VALUES = new Set([
  'student',
  'academic_staff',
  'amfn',
  'researcher',
  'sound_designer',
  'composer',
  'evaluation_test',
  'commercial_rd',
  'other'
]);

function parseAllowedOrigins(env: Env): Set<string> {
  return new Set(
    env.ALLOWED_ORIGINS.split(',')
      .map((value) => value.trim())
      .filter(Boolean)
  );
}

function getOrigin(request: Request): string {
  return request.headers.get('Origin')?.trim() ?? '';
}

function isAllowedOrigin(origin: string, env: Env): boolean {
  if (!origin) return false;
  return parseAllowedOrigins(env).has(origin);
}

function withCorsHeaders(headers: Headers, origin: string, env: Env): Headers {
  if (isAllowedOrigin(origin, env)) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Vary', 'Origin');
    headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type');
  }
  return headers;
}

function jsonResponse(payload: unknown, status: number, origin: string, env: Env): Response {
  const headers = withCorsHeaders(new Headers({ 'Content-Type': 'application/json; charset=utf-8' }), origin, env);
  return new Response(JSON.stringify(payload), { status, headers });
}

function textResponse(text: string, status: number, origin: string, env: Env): Response {
  const headers = withCorsHeaders(new Headers({ 'Content-Type': 'text/plain; charset=utf-8' }), origin, env);
  return new Response(text, { status, headers });
}

function normalizeText(value: unknown, max = 300): string {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

function normalizePurposes(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => normalizeText(item, 60)).filter((item) => PURPOSE_VALUES.has(item)))];
}

function extractPayload(body: unknown): DownloadPayload | null {
  if (!body || typeof body !== 'object') return null;
  const input = body as Record<string, unknown>;

  return {
    firstName: normalizeText(input.firstName, 80),
    lastName: normalizeText(input.lastName, 80),
    email: normalizeText(input.email, 180).toLowerCase(),
    purposes: normalizePurposes(input.purposes),
    purposeOther: normalizeText(input.purposeOther, 280),
    institution: normalizeText(input.institution, 120),
    consentTerms: input.consentTerms === true,
    consentStats: input.consentStats === true,
    consentUpdates: input.consentUpdates === true,
    lang: normalizeText(input.lang, 10),
    pluginVersion: normalizeText(input.pluginVersion, 64),
    website: normalizeText(input.website, 180)
  };
}

function validatePayload(payload: DownloadPayload): string | null {
  if (payload.website) return 'Validation failed.';
  if (payload.firstName.length < 2) return 'First name is required.';
  if (payload.lastName.length < 2) return 'Last name is required.';
  if (!EMAIL_REGEX.test(payload.email)) return 'Email format is invalid.';
  if (!payload.consentTerms) return 'Terms consent is required.';
  if (!payload.consentUpdates) return 'Updates consent is required.';
  if (payload.purposes.length === 0 && payload.purposeOther.length < 3) return 'At least one use purpose is required.';
  if (payload.purposes.includes('other') && payload.purposeOther.length < 3) return 'Please describe other purpose.';
  return null;
}

async function sha256Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function getClientIp(request: Request): string {
  const cfIp = request.headers.get('CF-Connecting-IP')?.trim();
  if (cfIp) return cfIp;
  const forwarded = request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim();
  if (forwarded) return forwarded;
  return 'unknown';
}

async function handleDownload(request: Request, env: Env): Promise<Response> {
  const origin = getOrigin(request);
  if (!isAllowedOrigin(origin, env)) {
    return jsonResponse({ error: 'forbidden', message: 'Origin is not allowed.' }, 403, origin, env);
  }

  if (!request.headers.get('Content-Type')?.includes('application/json')) {
    return jsonResponse({ error: 'invalid_content_type', message: 'Content-Type must be application/json.' }, 415, origin, env);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'invalid_json', message: 'Invalid JSON payload.' }, 400, origin, env);
  }

  const payload = extractPayload(body);
  if (!payload) {
    return jsonResponse({ error: 'invalid_body', message: 'Invalid request body.' }, 400, origin, env);
  }

  const validationError = validatePayload(payload);
  if (validationError) {
    return jsonResponse({ error: 'validation_error', message: validationError }, 400, origin, env);
  }

  const clientIp = getClientIp(request);
  const ipHash = await sha256Hex(`${clientIp}:${env.IP_HASH_SALT}`);
  const now = Date.now();

  const limitRecord = await env.DB.prepare(
    'SELECT COUNT(*) AS total FROM downloads WHERE ip_hash = ?1 AND created_at_ms >= ?2'
  )
    .bind(ipHash, now - RATE_LIMIT_WINDOW_MS)
    .first<{ total: number | string }>();

  const attemptCount = Number(limitRecord?.total ?? 0);
  if (attemptCount >= RATE_LIMIT_MAX) {
    return jsonResponse({ error: 'rate_limited', message: 'Too many requests. Try again later.' }, 429, origin, env);
  }

  const id = crypto.randomUUID();
  const createdAt = new Date(now).toISOString();
  const userAgent = normalizeText(request.headers.get('User-Agent'), 300);

  const insert = await env.DB.prepare(
    `
      INSERT INTO downloads (
        id, created_at, created_at_ms, first_name, last_name, email,
        purposes_json, purpose_other, institution,
        consent_terms, consent_stats, consent_updates,
        lang, plugin_version, user_agent, ip_hash
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
    `
  )
    .bind(
      id,
      createdAt,
      now,
      payload.firstName,
      payload.lastName,
      payload.email,
      JSON.stringify(payload.purposes),
      payload.purposeOther || null,
      payload.institution || null,
      payload.consentTerms ? 1 : 0,
      payload.consentStats ? 1 : 0,
      payload.consentUpdates ? 1 : 0,
      payload.lang || null,
      payload.pluginVersion || null,
      userAgent || null,
      ipHash
    )
    .run();

  if (!insert.success) {
    return jsonResponse({ error: 'db_insert_failed', message: 'Could not store download request.' }, 500, origin, env);
  }

  return jsonResponse(
    {
      downloadUrl: env.DOWNLOAD_URL,
      sha256: env.DOWNLOAD_SHA256
    },
    200,
    origin,
    env
  );
}

async function handleOptions(request: Request, env: Env): Promise<Response> {
  const origin = getOrigin(request);
  if (!isAllowedOrigin(origin, env)) {
    return jsonResponse({ error: 'forbidden', message: 'Origin is not allowed.' }, 403, origin, env);
  }
  return textResponse('', 204, origin, env);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health' && request.method === 'GET') {
      return new Response('ok', { status: 200 });
    }

    if (url.pathname === '/download' && request.method === 'OPTIONS') {
      return handleOptions(request, env);
    }

    if (url.pathname === '/download' && request.method === 'POST') {
      return handleDownload(request, env);
    }

    return jsonResponse({ error: 'not_found', message: 'Route not found.' }, 404, getOrigin(request), env);
  }
};
