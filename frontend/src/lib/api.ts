export type Result<T> =
  | { success: true; data: T }
  | { success: false; error: string };

const BASE_URL = "/api/";
const REQUEST_TIMEOUT_MS = 8000;
const GENERIC_ERROR = "Network error occurred";
const ACTION_FAILED = "Action failed";

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

function buildUrl(path: string): string {
  const trimmed = path.startsWith("/") ? path.slice(1) : path;
  return `${BASE_URL}${trimmed}`;
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<Result<T>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(buildUrl(path), {
      method: options.method ?? "GET",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...options.headers,
      },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
      credentials: "same-origin",
      mode: "same-origin",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });

    if (!response.ok) {
      return { success: false, error: ACTION_FAILED };
    }

    const data = (await response.json()) as T;
    return { success: true, data };
  } catch {
    return { success: false, error: GENERIC_ERROR };
  } finally {
    clearTimeout(timeoutId);
  }
}

export const api = {
  get: <T>(path: string) => apiRequest<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    apiRequest<T>(path, { method: "POST", body }),
  put: <T>(path: string, body?: unknown) =>
    apiRequest<T>(path, { method: "PUT", body }),
  patch: <T>(path: string, body?: unknown) =>
    apiRequest<T>(path, { method: "PATCH", body }),
  delete: <T>(path: string) => apiRequest<T>(path, { method: "DELETE" }),
};
