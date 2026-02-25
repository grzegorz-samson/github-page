import { API_BASE } from './config';

export interface ContactPayload {
  name?: string;
  email: string;
  subject?: string;
  message: string;
  lang: string;
  sourcePath?: string;
  website?: string;
}

export interface ContactResponse {
  ok: true;
  delivered: boolean;
}

export class ContactFormApiError extends Error {
  status: number;
  details: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ContactFormApiError';
    this.status = status;
    this.details = details;
  }
}

export async function fetchContactMessage(
  payload: ContactPayload,
  signal?: AbortSignal
): Promise<ContactResponse> {
  if (!API_BASE) {
    throw new ContactFormApiError(
      'PUBLIC_API_BASE is not configured. Set it to your Cloudflare Worker URL.',
      500
    );
  }

  const response = await fetch(`${API_BASE}/contact`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload),
    signal
  });

  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const message =
      typeof data === 'object' && data && 'message' in data && typeof data.message === 'string'
        ? data.message
        : 'Contact request failed.';
    throw new ContactFormApiError(message, response.status, data);
  }

  if (
    typeof data !== 'object' ||
    !data ||
    !('ok' in data) ||
    !('delivered' in data) ||
    data.ok !== true ||
    typeof data.delivered !== 'boolean'
  ) {
    throw new ContactFormApiError('Invalid response from contact API.', 502, data);
  }

  return {
    ok: true,
    delivered: data.delivered
  };
}
