const rawApiBase = (import.meta.env.PUBLIC_API_BASE ?? '').trim();

export const API_BASE = rawApiBase.replace(/\/$/, '');
