import { API_BASE } from './config';

export interface DownloadGatePayload {
  firstName: string;
  lastName: string;
  email: string;
  purposes: string[];
  purposeOther?: string;
  institution?: string;
  consentTerms: boolean;
  consentStats?: boolean;
  consentUpdates: boolean;
  lang: string;
  pluginVersion: string;
  website?: string;
}

export interface DownloadGateResponse {
  downloadUrl: string;
  sha256: string;
  expiresAt?: string;
}

export class DownloadGateApiError extends Error {
  status: number;
  details: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'DownloadGateApiError';
    this.status = status;
    this.details = details;
  }
}

export async function fetchDownloadLink(
  payload: DownloadGatePayload,
  signal?: AbortSignal
): Promise<DownloadGateResponse> {
  if (!API_BASE) {
    throw new DownloadGateApiError(
      'PUBLIC_API_BASE is not configured. Set it to your Cloudflare Worker URL.',
      500
    );
  }

  const response = await fetch(`${API_BASE}/download`, {
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
        : 'Download request failed.';
    throw new DownloadGateApiError(message, response.status, data);
  }

  if (
    typeof data !== 'object' ||
    !data ||
    !('downloadUrl' in data) ||
    !('sha256' in data) ||
    typeof data.downloadUrl !== 'string' ||
    typeof data.sha256 !== 'string'
  ) {
    throw new DownloadGateApiError('Invalid response from download API.', 502, data);
  }

  return {
    downloadUrl: data.downloadUrl,
    sha256: data.sha256,
    expiresAt: typeof data.expiresAt === 'string' ? data.expiresAt : undefined
  };
}
