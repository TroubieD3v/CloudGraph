import type { Analysis, Demo, DiffResult, HistoryItem, Simulation } from "./types";

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* not JSON */
    }
    throw new Error(msg);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  demos: () => request<Demo[]>("GET", "/api/demos"),
  history: () => request<HistoryItem[]>("GET", "/api/analyses"),
  get: (id: string) => request<Analysis>("GET", `/api/analyses/${id}`),
  remove: (id: string) => request<void>("DELETE", `/api/analyses/${id}`),
  analyzeDemo: (demo: string) => request<Analysis>("POST", "/api/analyses", { demo }),
  analyzeFiles: (name: string, files: { name: string; content: string }[]) =>
    request<Analysis>("POST", "/api/analyses", { name, files }),
  simulate: (id: string, fixes: string[]) => request<Simulation>("POST", `/api/analyses/${id}/simulate`, { fixes }),
  patch: (id: string, fixes: string[]) =>
    request<{ patch: string; manual: string[] }>("POST", `/api/analyses/${id}/patch`, { fixes }),
  diff: (a: string, b: string) => request<DiffResult>("GET", `/api/diff?a=${a}&b=${b}`),
};
