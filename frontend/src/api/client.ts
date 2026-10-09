// API client for /api/studio/* (studio/docs/API.md). With VITE_MOCK=1 every call is answered by the
// in-browser mock (mockData.ts + mockRender.ts) instead of the backend.
import type { ApplyConfirm, ApplyEvent, AuditResp, AuthInfo, ContextInfo, Ctx, Defaults, DiffResult, GatewaysResp, Health, Intent, Inventory, ModelArmorResp, RenderResult } from "./types";

export const IS_MOCK = import.meta.env.VITE_MOCK === "1";
const BASE = "/api/studio";

export class ApiError extends Error {
  status: number;
  constructor(status: number, msg: string) {
    super(msg);
    this.status = status;
  }
}

function qs(ctx: Ctx, refresh?: boolean): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(ctx)) if (v) p.set(k, String(v));
  if (refresh) p.set("refresh", "1");
  return p.toString();
}

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(BASE + path, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  const text = await r.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* not JSON */
  }
  if (!r.ok) {
    const detail = (body as { detail?: unknown } | null)?.detail;
    throw new ApiError(r.status, typeof detail === "string" ? detail : text.slice(0, 300) || r.statusText);
  }
  return body as T;
}

async function mock<T>(fn: (m: typeof import("./mock")) => T, ms = 280): Promise<T> {
  const m = await import("./mock");
  await new Promise((res) => setTimeout(res, ms + Math.random() * 200));
  return fn(m);
}

export const api = {
  health: (): Promise<Health> => (IS_MOCK ? mock(() => ({ ok: true, version: "mock" }), 50) : http("/health")),
  defaults: (): Promise<Defaults> => (IS_MOCK ? mock(() => ({ project: "my-demo-project", region: "us-east4" }), 50) : http("/defaults")),
  context: (ctx: Ctx, refresh = false): Promise<ContextInfo> => (IS_MOCK ? mock((m) => m.context(ctx), 600) : http(`/context?${qs(ctx, refresh)}`)),
  gateways: (ctx: Ctx, refresh = false): Promise<GatewaysResp> => (IS_MOCK ? mock((m) => m.gateways(ctx)) : http(`/gateways?${qs(ctx, refresh)}`)),
  modelArmor: (ctx: Ctx, refresh = false): Promise<ModelArmorResp> => (IS_MOCK ? mock((m) => m.modelArmor(ctx)) : http(`/model-armor?${qs(ctx, refresh)}`)),
  inventory: (ctx: Ctx, refresh = false): Promise<Inventory> => (IS_MOCK ? mock((m) => m.inventory(ctx), 450) : http(`/inventory?${qs(ctx, refresh)}`)),
  audit: (ctx: Ctx, refresh = false): Promise<AuditResp> => (IS_MOCK ? mock((m) => m.audit(ctx), 500) : http(`/audit?${qs(ctx, refresh)}`)),
  render: (ctx: Ctx, intents: Intent[]): Promise<RenderResult> =>
    IS_MOCK ? mock((m) => m.render(ctx, intents), 120) : http("/render", { method: "POST", body: JSON.stringify({ context: ctx, intents }) }),
  diff: (ctx: Ctx, intents: Intent[]): Promise<DiffResult> =>
    IS_MOCK ? mock((m) => m.diff(ctx, intents), 160) : http("/diff", { method: "POST", body: JSON.stringify({ context: ctx, intents }) }),
  auth: (ctx: Ctx, refresh = false): Promise<AuthInfo> => (IS_MOCK ? mock((m) => m.auth(ctx), 250) : http(`/auth?${qs(ctx, refresh)}`)),
  /** POST /apply and call onEvent for every streamed event (NDJSON, or SSE `data:` lines). */
  apply: async (ctx: Ctx, intents: Intent[], confirm: ApplyConfirm, onEvent: (e: ApplyEvent) => void, signal?: AbortSignal): Promise<void> => {
    if (IS_MOCK) {
      const m = await import("./mock");
      for await (const e of m.applyStream(ctx, intents, confirm, signal)) onEvent(e);
      return;
    }
    const r = await fetch(BASE + "/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/x-ndjson, text/event-stream" },
      body: JSON.stringify({ context: ctx, intents, confirm }),
      signal,
    });
    if (!r.ok || !r.body) {
      const text = await r.text().catch(() => "");
      let detail: unknown = null;
      try {
        detail = JSON.parse(text)?.detail;
      } catch {
        /* not JSON */
      }
      throw new ApiError(r.status, typeof detail === "string" ? detail : text.slice(0, 300) || r.statusText);
    }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    const line = (raw: string) => {
      let l = raw.trim();
      if (!l || l.startsWith(":") || l.startsWith("event:") || l.startsWith("id:") || l.startsWith("retry:")) return;
      if (l.startsWith("data:")) l = l.slice(5).trim();
      try {
        onEvent(JSON.parse(l) as ApplyEvent);
      } catch {
        /* ignore a malformed line */
      }
    };
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const parts = buf.split("\n");
      buf = parts.pop() ?? "";
      parts.forEach(line);
    }
    line(buf + dec.decode());
  },
};
