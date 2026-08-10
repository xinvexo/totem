import type { EntryPayload, ExportFile, TotpEntry } from "./types";

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (init.method && init.method !== "GET") {
    headers.set("X-Totem-Request", "1");
  }

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "same-origin",
  });
  if (response.status === 204) {
    return undefined as T;
  }

  const raw = await response.text();
  let data: unknown = undefined;
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = undefined;
    }
  }
  if (!response.ok) {
    const body = data as { error?: string; message?: string } | undefined;
    throw new ApiError(
      response.status,
      body?.error ?? "request_failed",
      body?.message ?? "The request could not be completed",
    );
  }
  return data as T;
}

export function getSession() {
  return request<{ authenticated: boolean }>("/api/session");
}

export function login(password: string) {
  return request<{ authenticated: true }>("/api/login", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function logout() {
  return request<void>("/api/logout", { method: "POST" });
}

export function getEntries() {
  return request<TotpEntry[]>("/api/entries");
}

export function createEntry(payload: EntryPayload) {
  return request<TotpEntry>("/api/entries", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateEntry(id: number, payload: EntryPayload) {
  return request<TotpEntry>(`/api/entries/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function deleteEntry(id: number) {
  return request<void>(`/api/entries/${id}`, { method: "DELETE" });
}

export function getSecret(id: number) {
  return request<{ secret: string }>(`/api/entries/${id}/secret`);
}

export function getOtpAuthUri(id: number) {
  return request<{ uri: string }>(`/api/entries/${id}/uri`);
}

export function exportEntries() {
  return request<ExportFile>("/api/export");
}

export function importEntries(payload: ExportFile) {
  return request<{ imported: number }>("/api/import", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
