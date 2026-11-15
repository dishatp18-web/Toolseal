export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

const SESSION_TOKEN_KEY = 'toolseal_session_token';

export function getClientSessionToken(): string | null {
  try {
    return window.sessionStorage.getItem(SESSION_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setClientSessionToken(token: string | null | undefined) {
  try {
    if (token) {
      window.sessionStorage.setItem(SESSION_TOKEN_KEY, token);
    } else {
      window.sessionStorage.removeItem(SESSION_TOKEN_KEY);
    }
  } catch {
    // Ignore restricted storage contexts
  }
}

export function clearClientSessionToken() {
  setClientSessionToken(null);
}

type UnauthorizedHandler = () => void;
let onUnauthorizedCallback: UnauthorizedHandler | null = null;

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  onUnauthorizedCallback = handler;
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  let res: Response;
  const token = getClientSessionToken();
  const mergedHeaders = new Headers({
    'Content-Type': 'application/json',
  });
  if (token) {
    mergedHeaders.set('Authorization', `Bearer ${token}`);
  }
  if (options?.headers) {
    const incoming = new Headers(options.headers);
    incoming.forEach((value, key) => {
      mergedHeaders.set(key, value);
    });
  }

  try {
    res = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: mergedHeaders,
    });
  } catch {
    throw new ApiError('Network connection to TOOLSEAL backend failed. Verify the server is running.', 0, 'NETWORK_ERROR');
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Only reset frontend auth state when the backend explicitly reports an invalid/expired TOOLSEAL session.
    // Unrelated errors (403 RBAC denials, 404/500 API failures, or external webhook 401 checks) never log out the user.
    if (res.status === 401 && data?.code === 'UNAUTHENTICATED' && !url.startsWith('/api/auth/')) {
      clearClientSessionToken();
      onUnauthorizedCallback?.();
    }
    throw new ApiError(
      data.error || `Request failed with HTTP ${res.status}`,
      res.status,
      typeof data.code === 'string' ? data.code : undefined
    );
  }
  return data as T;
}

export const api = {
  get: <T>(url: string) => request<T>(url),
  post: <T>(url: string, body?: unknown) =>
    request<T>(url, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
  put: <T>(url: string, body?: unknown) =>
    request<T>(url, { method: 'PUT', body: body !== undefined ? JSON.stringify(body) : undefined }),
  patch: <T>(url: string, body?: unknown) =>
    request<T>(url, { method: 'PATCH', body: body !== undefined ? JSON.stringify(body) : undefined }),
};

export function formatUtcTime(isoOrSqlite: string | null | undefined): string {
  if (!isoOrSqlite) return '—';
  const normalized = isoOrSqlite.includes('T') ? isoOrSqlite : isoOrSqlite.replace(' ', 'T') + 'Z';
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return isoOrSqlite;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}
