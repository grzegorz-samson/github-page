import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.ts';

const origin = 'https://example.com';

function setup(overrides: Record<string, unknown> = {}) {
  const calls: { dbReads: number; inserts: number; mail: unknown[] } = { dbReads: 0, inserts: 0, mail: [] };
  const env = {
    ALLOWED_ORIGINS: origin,
    IP_HASH_SALT: 'test-salt',
    DATA_ENCRYPTION_KEY: 'MDEyMzQ1Njc4OWFiY2RlZg==',
    TURNSTILE_SECRET_KEY: 'turnstile-secret',
    RESEND_API_KEY: 'resend-secret',
    CONTACT_TO_EMAIL: 'owner@example.net',
    CONTACT_FROM_EMAIL: 'Website <contact@example.net>',
    DB: {
      prepare(sql: string) {
        return {
          bind(...values: unknown[]) {
            return {
              async first() { calls.dbReads += 1; return { total: 0 }; },
              async run() { if (sql.trim().startsWith('INSERT')) calls.inserts += 1; return { success: true }; },
              values
            };
          }
        };
      }
    },
    ...overrides
  };
  const send = async (payload: Record<string, unknown> = {}) => worker.fetch(new Request('https://api.example/contact', {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Test', email: 'sender@example.org', subject: 'Hello', message: 'A sufficiently long message', lang: 'en', sourcePath: '/en/bio/', turnstileToken: 'valid-token', ...payload })
  }), env as never);
  return { calls, env, send };
}

function installFetch(siteverify: unknown, resend: { status: number; body?: string } = { status: 200 }) {
  const original = globalThis.fetch;
  const urls: string[] = [];
  const requests: RequestInit[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    urls.push(url);
    requests.push(init ?? {});
    if (url.includes('siteverify')) {
      return new Response(JSON.stringify(siteverify), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(resend.body ?? '{}', { status: resend.status });
  }) as typeof fetch;
  return { urls, requests, restore: () => { globalThis.fetch = original; } };
}

test('CAPTCHA failures and mismatched hostname/action have no database or email effects', async () => {
  for (const verification of [
    { success: false, hostname: 'example.com', action: 'contact' },
    { success: true, hostname: 'attacker.example', action: 'contact' },
    { success: true, hostname: 'example.com', action: 'other' }
  ]) {
    const mock = installFetch(verification);
    try {
      const { calls, send } = setup();
      const response = await send();
      assert.equal(response.status, 400);
      assert.equal((await response.json() as { error: string }).error, 'captcha_failed');
      assert.equal(calls.dbReads, 0);
      assert.equal(calls.inserts, 0);
      assert.equal(mock.urls.length, 1);
    } finally { mock.restore(); }
  }
});

test('valid CAPTCHA sends to configured recipient with sender as reply-to', async () => {
  const mock = installFetch({ success: true, hostname: 'example.com', action: 'contact' });
  try {
    const { calls, send } = setup();
    const response = await send();
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, delivered: true });
    assert.equal(calls.dbReads, 1);
    assert.equal(calls.inserts, 1);
    const mail = JSON.parse(String(mock.requests[1].body)) as { to: string[]; reply_to: string; from: string };
    assert.deepEqual(mail.to, ['owner@example.net']);
    assert.equal(mail.reply_to, 'sender@example.org');
    assert.equal(mail.from, 'Website <contact@example.net>');
  } finally { mock.restore(); }
});

test('Resend failure is stored and reported as not delivered without exposing provider details', async () => {
  const mock = installFetch({ success: true, hostname: 'example.com', action: 'contact' }, { status: 401, body: 'secret provider detail' });
  try {
    const { calls, send } = setup();
    const response = await send();
    assert.deepEqual(await response.json(), { ok: true, delivered: false });
    assert.equal(calls.inserts, 1);
  } finally { mock.restore(); }
});

test('missing Turnstile configuration fails closed before database access', async () => {
  const mock = installFetch({ success: true, hostname: 'example.com', action: 'contact' });
  try {
    const { calls, send } = setup({ TURNSTILE_SECRET_KEY: '' });
    const response = await send();
    assert.equal(response.status, 503);
    assert.equal((await response.json() as { error: string }).error, 'captcha_unavailable');
    assert.equal(calls.dbReads, 0);
    assert.equal(mock.urls.length, 0);
  } finally { mock.restore(); }
});

test('missing or oversized CAPTCHA tokens never reach providers or storage', async () => {
  const mock = installFetch({ success: true, hostname: 'example.com', action: 'contact' });
  try {
    for (const turnstileToken of ['', 'x'.repeat(2049)]) {
      const { calls, send } = setup();
      const response = await send({ turnstileToken });
      assert.equal(response.status, 400);
      assert.equal(calls.dbReads, 0);
      assert.equal(calls.inserts, 0);
    }
    assert.equal(mock.urls.length, 0);
  } finally { mock.restore(); }
});

test('missing mail configuration rejects before providers or storage', async () => {
  const mock = installFetch({ success: true, hostname: 'example.com', action: 'contact' });
  try {
    for (const missing of ['RESEND_API_KEY', 'CONTACT_TO_EMAIL', 'CONTACT_FROM_EMAIL']) {
      const { calls, send } = setup({ [missing]: '' });
      const response = await send();
      assert.equal(response.status, 503);
      assert.equal(calls.dbReads, 0);
      assert.equal(calls.inserts, 0);
    }
    assert.equal(mock.urls.length, 0);
  } finally { mock.restore(); }
});

test('unavailable CAPTCHA provider fails closed', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => { throw new Error('network timeout'); };
    const { calls, send } = setup();
    const response = await send();
    assert.equal(response.status, 503);
    assert.equal(calls.dbReads, 0);
    assert.equal(calls.inserts, 0);
  } finally { globalThis.fetch = original; }
});

test('database failure prevents email delivery', async () => {
  const mock = installFetch({ success: true, hostname: 'example.com', action: 'contact' });
  try {
    const { send } = setup({ DB: { prepare() { return { bind() { return {
      async first() { return { total: 0 }; },
      async run() { return { success: false }; }
    }; } }; } } });
    const response = await send();
    assert.equal(response.status, 500);
    assert.equal(mock.urls.length, 1);
  } finally { mock.restore(); }
});
