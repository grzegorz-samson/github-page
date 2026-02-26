
interface Env {
  DB: D1Database;
  DOWNLOAD_URL: string;
  DOWNLOAD_SHA256: string;
  ALLOWED_ORIGINS: string;
  IP_HASH_SALT: string;
  DATA_ENCRYPTION_KEY: string;
  DATA_HASH_PEPPER?: string;
  ADMIN_API_TOKEN?: string;
  RESEND_API_KEY?: string;
  CONTACT_TO_EMAIL?: string;
  CONTACT_FROM_EMAIL?: string;
}

interface DownloadPayload {
  firstName: string;
  lastName: string;
  email: string;
  purposes: string[];
  purposeOther: string;
  affiliations: string[];
  institutionOther: string;
  institution: string;
  consentTerms: boolean;
  consentStats: boolean;
  consentUpdates: boolean;
  lang: string;
  pluginVersion: string;
  website: string;
}

interface ContactPayload {
  name: string;
  email: string;
  subject: string;
  message: string;
  lang: string;
  sourcePath: string;
  website: string;
}

interface PageViewPayload {
  path: string;
  lang: string;
  referrer: string;
  website: string;
}

interface EventPayload {
  event: string;
  path: string;
  lang: string;
  pluginVersion: string;
  status: string;
  source: string;
  website: string;
}

const RATE_LIMIT_MAX = 5;
const CONTACT_RATE_LIMIT_MAX = 3;
const PAGEVIEW_RATE_LIMIT_MAX = 120;
const EVENT_RATE_LIMIT_MAX = 180;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PURPOSE_VALUES = new Set([
  'student',
  'academic_staff',
  'researcher',
  'sound_designer',
  'sound_director',
  'composer',
  'evaluation_test',
  'commercial_rd',
  'other'
]);
const AFFILIATION_VALUES = new Set(['amfn', 'other', 'none']);
const EVENT_VALUES = new Set([
  'download_modal_open',
  'download_submit_ok',
  'download_submit_error',
  'download_link_shown',
  'download_clicked'
]);
const EVENT_PATH_PREFIX = '/__event/';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let aesKeyCache: { source: string; keyPromise: Promise<CryptoKey> } | null = null;
let hmacKeyCache: { source: string; keyPromise: Promise<CryptoKey> } | null = null;

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
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token');
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

function hasUnsafeChars(value: string): boolean {
  return /[<>]/.test(value) || value.includes('|') || /[\u0000-\u001f\u007f]/.test(value);
}

function normalizePurposes(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => normalizeText(item, 60)).filter((item) => PURPOSE_VALUES.has(item)))];
}

function normalizeAffiliations(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => normalizeText(item, 30)).filter((item) => AFFILIATION_VALUES.has(item)))];
}

function extractDownloadPayload(body: unknown): DownloadPayload | null {
  if (!body || typeof body !== 'object') return null;
  const input = body as Record<string, unknown>;

  return {
    firstName: normalizeText(input.firstName, 80),
    lastName: normalizeText(input.lastName, 80),
    email: normalizeText(input.email, 180).toLowerCase(),
    purposes: normalizePurposes(input.purposes),
    purposeOther: normalizeText(input.purposeOther, 280),
    affiliations: normalizeAffiliations(input.affiliations),
    institutionOther: normalizeText(input.institutionOther, 140),
    institution: normalizeText(input.institution, 120),
    consentTerms: input.consentTerms === true,
    consentStats: input.consentStats === true,
    consentUpdates: input.consentUpdates === true,
    lang: normalizeText(input.lang, 10),
    pluginVersion: normalizeText(input.pluginVersion, 64),
    website: normalizeText(input.website, 180)
  };
}

function validateDownloadPayload(payload: DownloadPayload): string | null {
  if (payload.website) return 'Validation failed.';
  if (payload.firstName.length < 2) return 'First name is required.';
  if (payload.lastName.length < 2) return 'Last name is required.';
  if (!EMAIL_REGEX.test(payload.email)) return 'Email format is invalid.';
  if (!payload.consentTerms) return 'Terms consent is required.';
  if (!payload.consentUpdates) return 'Updates consent is required.';
  if (payload.purposes.length === 0 && payload.purposeOther.length < 3) return 'At least one use purpose is required.';
  if (payload.purposes.includes('other') && payload.purposeOther.length < 3) return 'Please describe other purpose.';
  if (payload.affiliations.length < 1) return 'At least one affiliation is required.';
  if (payload.affiliations.includes('none') && payload.affiliations.length > 1) {
    return 'Affiliation "none" cannot be combined with other options.';
  }
  if (payload.affiliations.includes('other') && payload.institutionOther.length < 2) return 'Please provide other institution.';
  return null;
}

function extractContactPayload(body: unknown): ContactPayload | null {
  if (!body || typeof body !== 'object') return null;
  const input = body as Record<string, unknown>;

  return {
    name: normalizeText(input.name, 100),
    email: normalizeText(input.email, 180).toLowerCase(),
    subject: normalizeText(input.subject, 140),
    message: normalizeText(input.message, 2000),
    lang: normalizeText(input.lang, 10),
    sourcePath: normalizeText(input.sourcePath, 200),
    website: normalizeText(input.website, 180)
  };
}

function validateContactPayload(payload: ContactPayload): string | null {
  if (payload.website) return 'Validation failed.';
  if (!EMAIL_REGEX.test(payload.email)) return 'Email format is invalid.';
  if (payload.message.length < 10) return 'Message must be at least 10 characters long.';
  return null;
}

function extractPageViewPayload(body: unknown): PageViewPayload | null {
  if (!body || typeof body !== 'object') return null;
  const input = body as Record<string, unknown>;

  return {
    path: normalizeText(input.path, 220),
    lang: normalizeText(input.lang, 10),
    referrer: normalizeText(input.referrer, 320),
    website: normalizeText(input.website, 160)
  };
}

function validatePageViewPayload(payload: PageViewPayload): string | null {
  if (payload.website) return 'Validation failed.';
  if (!payload.path.startsWith('/')) return 'Invalid path.';
  if (hasUnsafeChars(payload.path)) return 'Invalid path.';
  return null;
}

function extractEventPayload(body: unknown): EventPayload | null {
  if (!body || typeof body !== 'object') return null;
  const input = body as Record<string, unknown>;

  return {
    event: normalizeText(input.event, 80),
    path: normalizeText(input.path, 220),
    lang: normalizeText(input.lang, 10),
    pluginVersion: normalizeText(input.pluginVersion, 64),
    status: normalizeText(input.status, 40),
    source: normalizeText(input.source, 80),
    website: normalizeText(input.website, 160)
  };
}

function validateEventPayload(payload: EventPayload): string | null {
  if (payload.website) return 'Validation failed.';
  if (!EVENT_VALUES.has(payload.event)) return 'Invalid event.';
  if (!payload.path.startsWith('/')) return 'Invalid path.';
  if (hasUnsafeChars(payload.path)) return 'Invalid path.';
  if (payload.status && hasUnsafeChars(payload.status)) return 'Invalid status.';
  if (payload.source && hasUnsafeChars(payload.source)) return 'Invalid source.';
  return null;
}
function normalizeBase64(input: string): string {
  const replaced = input.trim().replace(/-/g, '+').replace(/_/g, '/');
  const pad = replaced.length % 4;
  if (pad === 0) return replaced;
  return replaced + '='.repeat(4 - pad);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const normalized = normalizeBase64(base64);
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function normalizeAadContext(value: string): string {
  const normalized = normalizeText(value, 240);
  return normalized || 'default';
}

async function getAesKey(env: Env): Promise<CryptoKey> {
  const source = normalizeText(env.DATA_ENCRYPTION_KEY, 3000);
  if (!source) {
    throw new Error('DATA_ENCRYPTION_KEY is missing.');
  }

  if (aesKeyCache && aesKeyCache.source === source) {
    return aesKeyCache.keyPromise;
  }

  const keyPromise = (async () => {
    const bytes = base64ToBytes(source);
    if (![16, 24, 32].includes(bytes.length)) {
      throw new Error('DATA_ENCRYPTION_KEY must be a base64-encoded 16/24/32-byte key.');
    }
    return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  })();

  aesKeyCache = { source, keyPromise };
  return keyPromise;
}

async function getHmacKey(env: Env): Promise<CryptoKey> {
  const source = normalizeText(env.DATA_HASH_PEPPER || env.IP_HASH_SALT, 4000);
  if (!source) {
    throw new Error('DATA_HASH_PEPPER or IP_HASH_SALT must be configured.');
  }

  if (hmacKeyCache && hmacKeyCache.source === source) {
    return hmacKeyCache.keyPromise;
  }

  const keyPromise = crypto.subtle.importKey('raw', encoder.encode(source), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign'
  ]);

  hmacKeyCache = { source, keyPromise };
  return keyPromise;
}

function toHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(value: string, env: Env): Promise<string> {
  const key = await getHmacKey(env);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(value));
  return toHex(signature);
}

async function encryptText(plain: string, env: Env, aadContext = 'default'): Promise<string> {
  const key = await getAesKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(normalizeAadContext(aadContext));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, encoder.encode(plain));
  return `enc:v2:${bytesToBase64(iv)}.${bytesToBase64(aad)}.${bytesToBase64(new Uint8Array(encrypted))}`;
}

async function encryptOptionalText(value: string, env: Env, aadContext = 'default'): Promise<string | null> {
  if (!value) return null;
  return encryptText(value, env, aadContext);
}

async function decryptStoredText(value: string | null | undefined, env: Env): Promise<string | null> {
  if (value == null) return null;
  if (!value.startsWith('enc:v1:') && !value.startsWith('enc:v2:')) {
    return value;
  }

  try {
    const key = await getAesKey(env);

    if (value.startsWith('enc:v2:')) {
      const payload = value.slice('enc:v2:'.length);
      const [ivBase64, aadBase64, encryptedBase64] = payload.split('.');
      if (!ivBase64 || !aadBase64 || !encryptedBase64) return '[decrypt_error]';

      const iv = base64ToBytes(ivBase64);
      const aad = base64ToBytes(aadBase64);
      const encrypted = base64ToBytes(encryptedBase64);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, encrypted);
      return decoder.decode(decrypted);
    }

    const payload = value.slice('enc:v1:'.length);
    const [ivBase64, encryptedBase64] = payload.split('.');
    if (!ivBase64 || !encryptedBase64) return '[decrypt_error]';

    const iv = base64ToBytes(ivBase64);
    const encrypted = base64ToBytes(encryptedBase64);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
    return decoder.decode(decrypted);
  } catch {
    return '[decrypt_error]';
  }
}

function getClientIp(request: Request): string {
  const cfIp = request.headers.get('CF-Connecting-IP')?.trim();
  if (cfIp) return cfIp;
  const forwarded = request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim();
  if (forwarded) return forwarded;
  return 'unknown';
}

async function getIpHash(request: Request, env: Env): Promise<string> {
  const ip = getClientIp(request);
  return hmacHex(`ip:${ip}`, env);
}

function normalizeReferrer(referrer: string): string {
  if (!referrer) return '';
  try {
    const url = new URL(referrer);
    return `${url.origin}${url.pathname}`.slice(0, 320);
  } catch {
    return '';
  }
}

function parsePositiveInt(value: string | null, fallbackValue: number, max: number): number {
  const parsed = Number.parseInt(value ?? '', 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallbackValue;
  return Math.min(parsed, max);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function isAdminAuthorized(request: Request, env: Env): boolean {
  const token = normalizeText(env.ADMIN_API_TOKEN, 400);
  if (!token) return false;

  const bearer = request.headers.get('Authorization')?.trim() ?? '';
  if (bearer.startsWith('Bearer ')) {
    return timingSafeEqual(bearer.slice(7).trim(), token);
  }

  const customHeader = request.headers.get('X-Admin-Token')?.trim() ?? '';
  if (customHeader) {
    return timingSafeEqual(customHeader, token);
  }

  return false;
}

async function isRateLimited(env: Env, table: 'downloads' | 'contact_messages' | 'pageviews', ipHash: string, max: number, now: number) {
  const query = `SELECT COUNT(*) AS total FROM ${table} WHERE ip_hash = ?1 AND created_at_ms >= ?2`;
  const limitRecord = await env.DB.prepare(query).bind(ipHash, now - RATE_LIMIT_WINDOW_MS).first<{ total: number | string }>();
  const attemptCount = Number(limitRecord?.total ?? 0);
  return attemptCount >= max;
}
async function sendContactEmail(payload: ContactPayload, env: Env): Promise<{ delivered: boolean; error: string | null }> {
  const apiKey = env.RESEND_API_KEY?.trim();
  const toEmail = env.CONTACT_TO_EMAIL?.trim();
  const fromEmail = env.CONTACT_FROM_EMAIL?.trim() || 'onboarding@resend.dev';

  if (!apiKey || !toEmail) {
    return { delivered: false, error: 'resend_not_configured' };
  }

  const subject = payload.subject || 'New contact message from website';
  const textBody = [
    `Name: ${payload.name || '-'}`,
    `Email: ${payload.email}`,
    `Lang: ${payload.lang || '-'}`,
    `Path: ${payload.sourcePath || '-'}`,
    '',
    'Message:',
    payload.message
  ].join('\n');

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [toEmail],
        subject,
        text: textBody,
        reply_to: payload.email
      })
    });

    if (!response.ok) {
      const details = normalizeText(await response.text(), 260);
      return { delivered: false, error: `resend_${response.status}${details ? `:${details}` : ''}` };
    }

    return { delivered: true, error: null };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'resend_request_failed';
    return { delivered: false, error: normalizeText(message, 260) || 'resend_request_failed' };
  }
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

  const payload = extractDownloadPayload(body);
  if (!payload) {
    return jsonResponse({ error: 'invalid_body', message: 'Invalid request body.' }, 400, origin, env);
  }

  const validationError = validateDownloadPayload(payload);
  if (validationError) {
    return jsonResponse({ error: 'validation_error', message: validationError }, 400, origin, env);
  }

  const ipHash = await getIpHash(request, env);
  const now = Date.now();

  if (await isRateLimited(env, 'downloads', ipHash, RATE_LIMIT_MAX, now)) {
    return jsonResponse({ error: 'rate_limited', message: 'Too many requests. Try again later.' }, 429, origin, env);
  }

  const id = crypto.randomUUID();
  const createdAt = new Date(now).toISOString();
  const userAgent = normalizeText(request.headers.get('User-Agent'), 300);
  const aad = (field: string) => `downloads:${id}:${field}`;

  const insert = await env.DB.prepare(
    `
      INSERT INTO downloads (
        id, created_at, created_at_ms, first_name, last_name, email, email_hash,
        purposes_json, purpose_other, institution, affiliations_json, institution_other,
        consent_terms, consent_stats, consent_updates,
        lang, plugin_version, user_agent, ip_hash
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
    `
  )
    .bind(
      id,
      createdAt,
      now,
      await encryptText(payload.firstName, env, aad('first_name')),
      await encryptText(payload.lastName, env, aad('last_name')),
      await encryptText(payload.email, env, aad('email')),
      await hmacHex(`email:${payload.email}`, env),
      await encryptText(JSON.stringify(payload.purposes), env, aad('purposes_json')),
      await encryptOptionalText(payload.purposeOther, env, aad('purpose_other')),
      await encryptOptionalText(payload.institution, env, aad('institution')),
      await encryptText(JSON.stringify(payload.affiliations), env, aad('affiliations_json')),
      await encryptOptionalText(payload.institutionOther, env, aad('institution_other')),
      payload.consentTerms ? 1 : 0,
      payload.consentStats ? 1 : 0,
      payload.consentUpdates ? 1 : 0,
      await encryptOptionalText(payload.lang, env, aad('lang')),
      await encryptOptionalText(payload.pluginVersion, env, aad('plugin_version')),
      await encryptOptionalText(userAgent, env, aad('user_agent')),
      ipHash
    )
    .run();

  if (!insert.success) {
    return jsonResponse({ error: 'db_insert_failed', message: 'Could not store download request.' }, 500, origin, env);
  }

  const downloadUrl = env.DOWNLOAD_URL.trim();
  if (!downloadUrl || downloadUrl.includes('DOWNLOAD_URL_PLACEHOLDER') || downloadUrl.startsWith('<')) {
    return jsonResponse(
      { error: 'download_config_missing', message: 'Download URL is not configured.' },
      500,
      origin,
      env
    );
  }

  let parsedDownloadUrl: URL | null = null;
  try {
    parsedDownloadUrl = new URL(downloadUrl);
  } catch {
    parsedDownloadUrl = null;
  }

  if (!parsedDownloadUrl || parsedDownloadUrl.protocol !== 'https:') {
    return jsonResponse(
      { error: 'download_config_invalid', message: 'Download URL must be a valid https URL.' },
      500,
      origin,
      env
    );
  }

  return jsonResponse(
    {
      downloadUrl,
      sha256: env.DOWNLOAD_SHA256
    },
    200,
    origin,
    env
  );
}
async function handleContact(request: Request, env: Env): Promise<Response> {
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

  const payload = extractContactPayload(body);
  if (!payload) {
    return jsonResponse({ error: 'invalid_body', message: 'Invalid request body.' }, 400, origin, env);
  }

  const validationError = validateContactPayload(payload);
  if (validationError) {
    return jsonResponse({ error: 'validation_error', message: validationError }, 400, origin, env);
  }

  const ipHash = await getIpHash(request, env);
  const now = Date.now();

  if (await isRateLimited(env, 'contact_messages', ipHash, CONTACT_RATE_LIMIT_MAX, now)) {
    return jsonResponse({ error: 'rate_limited', message: 'Too many requests. Try again later.' }, 429, origin, env);
  }

  const mailResult = await sendContactEmail(payload, env);
  const id = crypto.randomUUID();
  const createdAt = new Date(now).toISOString();
  const userAgent = normalizeText(request.headers.get('User-Agent'), 300);
  const aad = (field: string) => `contact_messages:${id}:${field}`;

  const insert = await env.DB.prepare(
    `
      INSERT INTO contact_messages (
        id, created_at, created_at_ms, name, email, email_hash, subject, message, lang, source_path,
        user_agent, ip_hash, email_sent, email_error
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
    `
  )
    .bind(
      id,
      createdAt,
      now,
      await encryptOptionalText(payload.name, env, aad('name')),
      await encryptText(payload.email, env, aad('email')),
      await hmacHex(`email:${payload.email}`, env),
      await encryptOptionalText(payload.subject, env, aad('subject')),
      await encryptText(payload.message, env, aad('message')),
      await encryptOptionalText(payload.lang, env, aad('lang')),
      await encryptOptionalText(payload.sourcePath, env, aad('source_path')),
      await encryptOptionalText(userAgent, env, aad('user_agent')),
      ipHash,
      mailResult.delivered ? 1 : 0,
      mailResult.error ? normalizeText(mailResult.error, 260) : null
    )
    .run();

  if (!insert.success) {
    return jsonResponse({ error: 'db_insert_failed', message: 'Could not store contact request.' }, 500, origin, env);
  }

  return jsonResponse({ ok: true, delivered: mailResult.delivered }, 200, origin, env);
}

async function handlePageview(request: Request, env: Env): Promise<Response> {
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

  const payload = extractPageViewPayload(body);
  if (!payload) {
    return jsonResponse({ error: 'invalid_body', message: 'Invalid request body.' }, 400, origin, env);
  }

  const validationError = validatePageViewPayload(payload);
  if (validationError) {
    return jsonResponse({ error: 'validation_error', message: validationError }, 400, origin, env);
  }

  const ipHash = await getIpHash(request, env);
  const now = Date.now();

  if (await isRateLimited(env, 'pageviews', ipHash, PAGEVIEW_RATE_LIMIT_MAX, now)) {
    return jsonResponse({ error: 'rate_limited', message: 'Too many requests. Try again later.' }, 429, origin, env);
  }

  const id = crypto.randomUUID();
  const createdAt = new Date(now).toISOString();
  const userAgent = normalizeText(request.headers.get('User-Agent'), 300);
  const userAgentHash = userAgent ? await hmacHex(`ua:${userAgent}`, env) : null;

  const insert = await env.DB.prepare(
    `
      INSERT INTO pageviews (
        id, created_at, created_at_ms, path, lang, referrer, ip_hash, user_agent_hash
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    `
  )
    .bind(id, createdAt, now, payload.path, payload.lang || null, normalizeReferrer(payload.referrer) || null, ipHash, userAgentHash)
    .run();

  if (!insert.success) {
    return jsonResponse({ error: 'db_insert_failed', message: 'Could not store analytics event.' }, 500, origin, env);
  }

  return textResponse('', 204, origin, env);
}

async function handleEvent(request: Request, env: Env): Promise<Response> {
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

  const payload = extractEventPayload(body);
  if (!payload) {
    return jsonResponse({ error: 'invalid_body', message: 'Invalid request body.' }, 400, origin, env);
  }

  const validationError = validateEventPayload(payload);
  if (validationError) {
    return jsonResponse({ error: 'validation_error', message: validationError }, 400, origin, env);
  }

  const ipHash = await getIpHash(request, env);
  const now = Date.now();

  if (await isRateLimited(env, 'pageviews', ipHash, EVENT_RATE_LIMIT_MAX, now)) {
    return jsonResponse({ error: 'rate_limited', message: 'Too many requests. Try again later.' }, 429, origin, env);
  }

  const id = crypto.randomUUID();
  const createdAt = new Date(now).toISOString();
  const userAgent = normalizeText(request.headers.get('User-Agent'), 300);
  const userAgentHash = userAgent ? await hmacHex(`ua:${userAgent}`, env) : null;
  const sourcePath = payload.path.startsWith('/') ? payload.path : '/';
  const referrer = [sourcePath, payload.status || '-', payload.pluginVersion || '-', payload.source || '-']
    .join('|')
    .slice(0, 320);

  const insert = await env.DB.prepare(
    `
      INSERT INTO pageviews (
        id, created_at, created_at_ms, path, lang, referrer, ip_hash, user_agent_hash
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    `
  )
    .bind(id, createdAt, now, `${EVENT_PATH_PREFIX}${payload.event}`, payload.lang || null, referrer, ipHash, userAgentHash)
    .run();

  if (!insert.success) {
    return jsonResponse({ error: 'db_insert_failed', message: 'Could not store event.' }, 500, origin, env);
  }

  return textResponse('', 204, origin, env);
}
async function handleAdminStats(request: Request, env: Env): Promise<Response> {
  const origin = getOrigin(request);
  if (!isAdminAuthorized(request, env)) {
    return jsonResponse({ error: 'unauthorized', message: 'Admin token is required.' }, 401, origin, env);
  }

  const url = new URL(request.url);
  const days = parsePositiveInt(url.searchParams.get('days'), 30, 365);
  const fromMs = Date.now() - days * 24 * 60 * 60 * 1000;

  const totals = await env.DB.prepare(
    `
      SELECT
        (SELECT COUNT(*) FROM downloads WHERE created_at_ms >= ?1) AS downloads_total,
        (SELECT COUNT(*) FROM contact_messages WHERE created_at_ms >= ?1) AS contacts_total,
        (SELECT COUNT(*) FROM pageviews WHERE created_at_ms >= ?1 AND path NOT LIKE '${EVENT_PATH_PREFIX}%') AS pageviews_total,
        (SELECT COUNT(*) FROM pageviews WHERE created_at_ms >= ?1 AND path LIKE '${EVENT_PATH_PREFIX}%') AS events_total,
        (SELECT COUNT(DISTINCT ip_hash) FROM pageviews WHERE created_at_ms >= ?1 AND path NOT LIKE '${EVENT_PATH_PREFIX}%') AS unique_visitors
    `
  )
    .bind(fromMs)
    .first<{
      downloads_total: number | string;
      contacts_total: number | string;
      pageviews_total: number | string;
      events_total: number | string;
      unique_visitors: number | string;
    }>();

  const pageviewsDailyRows = await env.DB.prepare(
    `
      SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total
      FROM pageviews
      WHERE created_at_ms >= ?1 AND path NOT LIKE '${EVENT_PATH_PREFIX}%'
      GROUP BY day
      ORDER BY day ASC
    `
  )
    .bind(fromMs)
    .all<{ day: string; total: number | string }>();

  const eventsDailyRows = await env.DB.prepare(
    `
      SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total
      FROM pageviews
      WHERE created_at_ms >= ?1 AND path LIKE '${EVENT_PATH_PREFIX}%'
      GROUP BY day
      ORDER BY day ASC
    `
  )
    .bind(fromMs)
    .all<{ day: string; total: number | string }>();

  const downloadsDailyRows = await env.DB.prepare(
    `
      SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total
      FROM downloads
      WHERE created_at_ms >= ?1
      GROUP BY day
      ORDER BY day ASC
    `
  )
    .bind(fromMs)
    .all<{ day: string; total: number | string }>();

  const contactsDailyRows = await env.DB.prepare(
    `
      SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total
      FROM contact_messages
      WHERE created_at_ms >= ?1
      GROUP BY day
      ORDER BY day ASC
    `
  )
    .bind(fromMs)
    .all<{ day: string; total: number | string }>();

  const topPathsRows = await env.DB.prepare(
    `
      SELECT path, COUNT(*) AS total
      FROM pageviews
      WHERE created_at_ms >= ?1 AND path NOT LIKE '${EVENT_PATH_PREFIX}%'
      GROUP BY path
      ORDER BY total DESC
      LIMIT 15
    `
  )
    .bind(fromMs)
    .all<{ path: string; total: number | string }>();

  const topReferrersRows = await env.DB.prepare(
    `
      SELECT referrer, COUNT(*) AS total
      FROM pageviews
      WHERE created_at_ms >= ?1 AND path NOT LIKE '${EVENT_PATH_PREFIX}%' AND referrer IS NOT NULL AND referrer <> ''
      GROUP BY referrer
      ORDER BY total DESC
      LIMIT 15
    `
  )
    .bind(fromMs)
    .all<{ referrer: string; total: number | string }>();

  const topIpHashesRows = await env.DB.prepare(
    `
      SELECT ip_hash, COUNT(*) AS total
      FROM pageviews
      WHERE created_at_ms >= ?1 AND path NOT LIKE '${EVENT_PATH_PREFIX}%'
      GROUP BY ip_hash
      ORDER BY total DESC
      LIMIT 15
    `
  )
    .bind(fromMs)
    .all<{ ip_hash: string; total: number | string }>();

  const topEventsRows = await env.DB.prepare(
    `
      SELECT path, COUNT(*) AS total
      FROM pageviews
      WHERE created_at_ms >= ?1 AND path LIKE '${EVENT_PATH_PREFIX}%'
      GROUP BY path
      ORDER BY total DESC
      LIMIT 15
    `
  )
    .bind(fromMs)
    .all<{ path: string; total: number | string }>();

  return jsonResponse(
    {
      range: { days },
      totals: {
        downloads: Number(totals?.downloads_total ?? 0),
        contacts: Number(totals?.contacts_total ?? 0),
        pageviews: Number(totals?.pageviews_total ?? 0),
        events: Number(totals?.events_total ?? 0),
        uniqueVisitors: Number(totals?.unique_visitors ?? 0)
      },
      daily: {
        pageviews: (pageviewsDailyRows.results ?? []).map((row) => ({ day: row.day, total: Number(row.total) })),
        events: (eventsDailyRows.results ?? []).map((row) => ({ day: row.day, total: Number(row.total) })),
        downloads: (downloadsDailyRows.results ?? []).map((row) => ({ day: row.day, total: Number(row.total) })),
        contacts: (contactsDailyRows.results ?? []).map((row) => ({ day: row.day, total: Number(row.total) }))
      },
      topPaths: (topPathsRows.results ?? []).map((row) => ({ path: row.path, total: Number(row.total) })),
      topEvents: (topEventsRows.results ?? []).map((row) => ({
        event: row.path.replace(EVENT_PATH_PREFIX, ''),
        total: Number(row.total)
      })),
      topReferrers: (topReferrersRows.results ?? []).map((row) => ({ referrer: row.referrer, total: Number(row.total) })),
      topIpHashes: (topIpHashesRows.results ?? []).map((row) => ({ ipHash: row.ip_hash, total: Number(row.total) }))
    },
    200,
    origin,
    env
  );
}
async function handleAdminRecords(request: Request, env: Env): Promise<Response> {
  const origin = getOrigin(request);
  if (!isAdminAuthorized(request, env)) {
    return jsonResponse({ error: 'unauthorized', message: 'Admin token is required.' }, 401, origin, env);
  }

  const url = new URL(request.url);
  const type = normalizeText(url.searchParams.get('type'), 20) || 'downloads';
  const limit = parsePositiveInt(url.searchParams.get('limit'), 50, 200);
  const offset = Math.max(0, Number.parseInt(url.searchParams.get('offset') ?? '0', 10) || 0);

  if (type === 'downloads') {
    const rows = await env.DB.prepare(
      `
        SELECT
          id, created_at, first_name, last_name, email, email_hash,
          purposes_json, purpose_other, institution, affiliations_json, institution_other,
          consent_terms, consent_stats, consent_updates, lang, plugin_version, user_agent, ip_hash
        FROM downloads
        ORDER BY created_at_ms DESC
        LIMIT ?1 OFFSET ?2
      `
    )
      .bind(limit, offset)
      .all<{
        id: string;
        created_at: string;
        first_name: string | null;
        last_name: string | null;
        email: string | null;
        email_hash: string | null;
        purposes_json: string | null;
        purpose_other: string | null;
        institution: string | null;
        affiliations_json: string | null;
        institution_other: string | null;
        consent_terms: number;
        consent_stats: number;
        consent_updates: number;
        lang: string | null;
        plugin_version: string | null;
        user_agent: string | null;
        ip_hash: string;
      }>();

    const items = await Promise.all(
      (rows.results ?? []).map(async (row) => {
        const purposesRaw = (await decryptStoredText(row.purposes_json, env)) ?? '[]';
        const affiliationsRaw = (await decryptStoredText(row.affiliations_json, env)) ?? '[]';

        let purposes: string[] = [];
        let affiliations: string[] = [];
        try {
          const parsed = JSON.parse(purposesRaw);
          if (Array.isArray(parsed)) purposes = parsed.map((item) => String(item));
        } catch {
          purposes = [];
        }
        try {
          const parsed = JSON.parse(affiliationsRaw);
          if (Array.isArray(parsed)) affiliations = parsed.map((item) => String(item));
        } catch {
          affiliations = [];
        }

        return {
          id: row.id,
          createdAt: row.created_at,
          firstName: await decryptStoredText(row.first_name, env),
          lastName: await decryptStoredText(row.last_name, env),
          email: await decryptStoredText(row.email, env),
          emailHash: row.email_hash,
          purposes,
          purposeOther: await decryptStoredText(row.purpose_other, env),
          institution: await decryptStoredText(row.institution, env),
          affiliations,
          institutionOther: await decryptStoredText(row.institution_other, env),
          consentTerms: Number(row.consent_terms) === 1,
          consentStats: Number(row.consent_stats) === 1,
          consentUpdates: Number(row.consent_updates) === 1,
          lang: await decryptStoredText(row.lang, env),
          pluginVersion: await decryptStoredText(row.plugin_version, env),
          userAgent: await decryptStoredText(row.user_agent, env),
          ipHash: row.ip_hash
        };
      })
    );

    return jsonResponse({ type, limit, offset, items }, 200, origin, env);
  }

  if (type === 'contacts') {
    const rows = await env.DB.prepare(
      `
        SELECT
          id, created_at, name, email, email_hash, subject, message, lang, source_path,
          user_agent, ip_hash, email_sent, email_error
        FROM contact_messages
        ORDER BY created_at_ms DESC
        LIMIT ?1 OFFSET ?2
      `
    )
      .bind(limit, offset)
      .all<{
        id: string;
        created_at: string;
        name: string | null;
        email: string | null;
        email_hash: string | null;
        subject: string | null;
        message: string | null;
        lang: string | null;
        source_path: string | null;
        user_agent: string | null;
        ip_hash: string;
        email_sent: number;
        email_error: string | null;
      }>();

    const items = await Promise.all(
      (rows.results ?? []).map(async (row) => ({
        id: row.id,
        createdAt: row.created_at,
        name: await decryptStoredText(row.name, env),
        email: await decryptStoredText(row.email, env),
        emailHash: row.email_hash,
        subject: await decryptStoredText(row.subject, env),
        message: await decryptStoredText(row.message, env),
        lang: await decryptStoredText(row.lang, env),
        sourcePath: await decryptStoredText(row.source_path, env),
        userAgent: await decryptStoredText(row.user_agent, env),
        ipHash: row.ip_hash,
        emailSent: Number(row.email_sent) === 1,
        emailError: row.email_error
      }))
    );

    return jsonResponse({ type, limit, offset, items }, 200, origin, env);
  }

  if (type === 'pageviews') {
    const rows = await env.DB.prepare(
      `
        SELECT id, created_at, path, lang, referrer, ip_hash, user_agent_hash
        FROM pageviews
        WHERE path NOT LIKE '${EVENT_PATH_PREFIX}%'
        ORDER BY created_at_ms DESC
        LIMIT ?1 OFFSET ?2
      `
    )
      .bind(limit, offset)
      .all<{
        id: string;
        created_at: string;
        path: string;
        lang: string | null;
        referrer: string | null;
        ip_hash: string;
        user_agent_hash: string | null;
      }>();

    const items = (rows.results ?? []).map((row) => ({
      id: row.id,
      createdAt: row.created_at,
      path: row.path,
      lang: row.lang,
      referrer: row.referrer,
      ipHash: row.ip_hash,
      userAgentHash: row.user_agent_hash
    }));

    return jsonResponse({ type, limit, offset, items }, 200, origin, env);
  }

  if (type === 'events') {
    const rows = await env.DB.prepare(
      `
        SELECT id, created_at, path, lang, referrer, ip_hash, user_agent_hash
        FROM pageviews
        WHERE path LIKE '${EVENT_PATH_PREFIX}%'
        ORDER BY created_at_ms DESC
        LIMIT ?1 OFFSET ?2
      `
    )
      .bind(limit, offset)
      .all<{
        id: string;
        created_at: string;
        path: string;
        lang: string | null;
        referrer: string | null;
        ip_hash: string;
        user_agent_hash: string | null;
      }>();

    const items = (rows.results ?? []).map((row) => {
      const [path = '', status = '', pluginVersion = '', source = ''] = (row.referrer ?? '').split('|');
      return {
        id: row.id,
        createdAt: row.created_at,
        event: row.path.replace(EVENT_PATH_PREFIX, ''),
        path,
        status,
        pluginVersion,
        source,
        lang: row.lang,
        ipHash: row.ip_hash,
        userAgentHash: row.user_agent_hash
      };
    });

    return jsonResponse({ type, limit, offset, items }, 200, origin, env);
  }

  return jsonResponse({ error: 'invalid_type', message: 'Supported types: downloads, contacts, pageviews, events.' }, 400, origin, env);
}

async function handleAdminReencrypt(request: Request, env: Env): Promise<Response> {
  const origin = getOrigin(request);
  if (!isAdminAuthorized(request, env)) {
    return jsonResponse({ error: 'unauthorized', message: 'Admin token is required.' }, 401, origin, env);
  }

  const legacyDownloads = await env.DB.prepare(
    `
      SELECT id, first_name, last_name, email, purpose_other, institution, institution_other, purposes_json, affiliations_json, lang, plugin_version, user_agent
      FROM downloads
      WHERE
        (first_name NOT LIKE 'enc:v1:%' AND first_name NOT LIKE 'enc:v2:%') OR
        (last_name NOT LIKE 'enc:v1:%' AND last_name NOT LIKE 'enc:v2:%') OR
        (email NOT LIKE 'enc:v1:%' AND email NOT LIKE 'enc:v2:%') OR
        (purpose_other IS NOT NULL AND purpose_other NOT LIKE 'enc:v1:%' AND purpose_other NOT LIKE 'enc:v2:%') OR
        (institution IS NOT NULL AND institution NOT LIKE 'enc:v1:%' AND institution NOT LIKE 'enc:v2:%') OR
        (institution_other IS NOT NULL AND institution_other NOT LIKE 'enc:v1:%' AND institution_other NOT LIKE 'enc:v2:%') OR
        (purposes_json NOT LIKE 'enc:v1:%' AND purposes_json NOT LIKE 'enc:v2:%') OR
        (affiliations_json NOT LIKE 'enc:v1:%' AND affiliations_json NOT LIKE 'enc:v2:%') OR
        (lang IS NOT NULL AND lang NOT LIKE 'enc:v1:%' AND lang NOT LIKE 'enc:v2:%') OR
        (plugin_version IS NOT NULL AND plugin_version NOT LIKE 'enc:v1:%' AND plugin_version NOT LIKE 'enc:v2:%') OR
        (user_agent IS NOT NULL AND user_agent NOT LIKE 'enc:v1:%' AND user_agent NOT LIKE 'enc:v2:%')
      LIMIT 1000
    `
  ).all<{
    id: string;
    first_name: string | null;
    last_name: string | null;
    email: string | null;
    purpose_other: string | null;
    institution: string | null;
    institution_other: string | null;
    purposes_json: string | null;
    affiliations_json: string | null;
    lang: string | null;
    plugin_version: string | null;
    user_agent: string | null;
  }>();

  let downloadsUpdated = 0;
  for (const row of legacyDownloads.results ?? []) {
    const firstName = (await decryptStoredText(row.first_name, env)) ?? '';
    const lastName = (await decryptStoredText(row.last_name, env)) ?? '';
    const email = (await decryptStoredText(row.email, env)) ?? '';
    const purposeOther = await decryptStoredText(row.purpose_other, env);
    const institution = await decryptStoredText(row.institution, env);
    const institutionOther = await decryptStoredText(row.institution_other, env);
    const purposesJson = (await decryptStoredText(row.purposes_json, env)) ?? '[]';
    const affiliationsJson = (await decryptStoredText(row.affiliations_json, env)) ?? '[]';
    const lang = await decryptStoredText(row.lang, env);
    const pluginVersion = await decryptStoredText(row.plugin_version, env);
    const userAgent = await decryptStoredText(row.user_agent, env);

    const aad = (field: string) => `downloads:${row.id}:${field}`;
    await env.DB.prepare(
      `
        UPDATE downloads
        SET
          first_name = ?1,
          last_name = ?2,
          email = ?3,
          email_hash = ?4,
          purpose_other = ?5,
          institution = ?6,
          institution_other = ?7,
          purposes_json = ?8,
          affiliations_json = ?9,
          lang = ?10,
          plugin_version = ?11,
          user_agent = ?12
        WHERE id = ?13
      `
    )
      .bind(
        await encryptText(firstName, env, aad('first_name')),
        await encryptText(lastName, env, aad('last_name')),
        await encryptText(email, env, aad('email')),
        await hmacHex(`email:${email.toLowerCase()}`, env),
        purposeOther ? await encryptText(purposeOther, env, aad('purpose_other')) : null,
        institution ? await encryptText(institution, env, aad('institution')) : null,
        institutionOther ? await encryptText(institutionOther, env, aad('institution_other')) : null,
        await encryptText(purposesJson, env, aad('purposes_json')),
        await encryptText(affiliationsJson, env, aad('affiliations_json')),
        lang ? await encryptText(lang, env, aad('lang')) : null,
        pluginVersion ? await encryptText(pluginVersion, env, aad('plugin_version')) : null,
        userAgent ? await encryptText(userAgent, env, aad('user_agent')) : null,
        row.id
      )
      .run();
    downloadsUpdated += 1;
  }

  const legacyContacts = await env.DB.prepare(
    `
      SELECT id, name, email, subject, message, lang, source_path, user_agent
      FROM contact_messages
      WHERE
        (name IS NOT NULL AND name NOT LIKE 'enc:v1:%' AND name NOT LIKE 'enc:v2:%') OR
        (email NOT LIKE 'enc:v1:%' AND email NOT LIKE 'enc:v2:%') OR
        (subject IS NOT NULL AND subject NOT LIKE 'enc:v1:%' AND subject NOT LIKE 'enc:v2:%') OR
        (message NOT LIKE 'enc:v1:%' AND message NOT LIKE 'enc:v2:%') OR
        (lang IS NOT NULL AND lang NOT LIKE 'enc:v1:%' AND lang NOT LIKE 'enc:v2:%') OR
        (source_path IS NOT NULL AND source_path NOT LIKE 'enc:v1:%' AND source_path NOT LIKE 'enc:v2:%') OR
        (user_agent IS NOT NULL AND user_agent NOT LIKE 'enc:v1:%' AND user_agent NOT LIKE 'enc:v2:%')
      LIMIT 1000
    `
  ).all<{
    id: string;
    name: string | null;
    email: string | null;
    subject: string | null;
    message: string | null;
    lang: string | null;
    source_path: string | null;
    user_agent: string | null;
  }>();

  let contactsUpdated = 0;
  for (const row of legacyContacts.results ?? []) {
    const name = await decryptStoredText(row.name, env);
    const email = (await decryptStoredText(row.email, env)) ?? '';
    const subject = await decryptStoredText(row.subject, env);
    const message = (await decryptStoredText(row.message, env)) ?? '';
    const lang = await decryptStoredText(row.lang, env);
    const sourcePath = await decryptStoredText(row.source_path, env);
    const userAgent = await decryptStoredText(row.user_agent, env);

    const aad = (field: string) => `contact_messages:${row.id}:${field}`;
    await env.DB.prepare(
      `
        UPDATE contact_messages
        SET
          name = ?1,
          email = ?2,
          email_hash = ?3,
          subject = ?4,
          message = ?5,
          lang = ?6,
          source_path = ?7,
          user_agent = ?8
        WHERE id = ?9
      `
    )
      .bind(
        name ? await encryptText(name, env, aad('name')) : null,
        await encryptText(email, env, aad('email')),
        await hmacHex(`email:${email.toLowerCase()}`, env),
        subject ? await encryptText(subject, env, aad('subject')) : null,
        await encryptText(message, env, aad('message')),
        lang ? await encryptText(lang, env, aad('lang')) : null,
        sourcePath ? await encryptText(sourcePath, env, aad('source_path')) : null,
        userAgent ? await encryptText(userAgent, env, aad('user_agent')) : null,
        row.id
      )
      .run();
    contactsUpdated += 1;
  }

  return jsonResponse({ ok: true, updated: { downloads: downloadsUpdated, contacts: contactsUpdated } }, 200, origin, env);
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

    if (
      ['/download', '/contact', '/analytics/pageview', '/event', '/admin/stats', '/admin/records', '/admin/reencrypt'].includes(url.pathname) &&
      request.method === 'OPTIONS'
    ) {
      return handleOptions(request, env);
    }

    if (url.pathname === '/download' && request.method === 'POST') {
      return handleDownload(request, env);
    }

    if (url.pathname === '/contact' && request.method === 'POST') {
      return handleContact(request, env);
    }

    if (url.pathname === '/analytics/pageview' && request.method === 'POST') {
      return handlePageview(request, env);
    }

    if (url.pathname === '/event' && request.method === 'POST') {
      return handleEvent(request, env);
    }

    if (url.pathname === '/admin/stats' && request.method === 'GET') {
      return handleAdminStats(request, env);
    }

    if (url.pathname === '/admin/records' && request.method === 'GET') {
      return handleAdminRecords(request, env);
    }

    if (url.pathname === '/admin/reencrypt' && request.method === 'POST') {
      return handleAdminReencrypt(request, env);
    }

    return jsonResponse({ error: 'not_found', message: 'Route not found.' }, 404, getOrigin(request), env);
  }
};
