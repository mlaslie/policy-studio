// App state: context (persisted), discovery data with Sync, the policy cart (persisted), navigation,
// builder hand-off, the Learn panel and toasts. One React context; no external state library.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "./api/client";
import type { ApplyConfirm, AuditResp, AuthInfo, ContextInfo, Ctx, GatewaysResp, Intent, Inventory, ModelArmorResp } from "./api/types";
import { sameChange, toList, type ApplyRun } from "./lib/apply";
import { load, save } from "./lib/util";
import { intentKey, newId } from "./lib/policy";

export type Loadable<T> = { data: T | null; loading: boolean; error: string | null };
const empty = <T,>(): Loadable<T> => ({ data: null, loading: false, error: null });

export const STEPS = [
  { n: 0, key: "context", title: "Context", sub: "Project and region" },
  { n: 1, key: "gateways", title: "Gateways", sub: "Where traffic is checked" },
  { n: 2, key: "model-armor", title: "Model Armor", sub: "Content screening" },
  { n: 3, key: "inventory", title: "Inventory", sub: "Agents, tools and APIs" },
  { n: 4, key: "build", title: "Build a policy", sub: "Who can call what" },
  { n: 5, key: "review", title: "Review & output", sub: "Commands and diff" },
  { n: 6, key: "apply", title: "Apply", sub: "Make the changes" },
  { n: 7, key: "audit", title: "Audit", sub: "What's in place today" },
] as const;
export type StepN = (typeof STEPS)[number]["n"];

type Toast = { id: number; text: string; tone?: "ok" | "warn" };

type Studio = {
  ctx: Ctx;
  setCtx: (c: Ctx) => void;
  ctxInfo: Loadable<ContextInfo>;
  gateways: Loadable<GatewaysResp>;
  modelArmor: Loadable<ModelArmorResp>;
  inventory: Loadable<Inventory>;
  audit: Loadable<AuditResp>;
  syncing: boolean;
  syncedAt: number | null;
  sync: (refresh?: boolean, c?: Ctx) => Promise<void>;
  cart: Intent[];
  addIntents: (items: Intent[]) => void;
  updateIntent: (id: string, it: Intent) => void;
  removeIntent: (id: string) => void;
  duplicateIntent: (id: string) => void;
  clearCart: () => void;
  step: StepN;
  goto: (s: StepN) => void;
  draft: { intent: Partial<Intent>; editId?: string; mode?: "grant" | "revoke"; seq: number } | null;
  openBuilder: (intent: Partial<Intent>, opts?: { editId?: string; mode?: "grant" | "revoke" }) => void;
  reviewFocus: string | null;
  openReview: (id?: string | null) => void;
  learnOpen: boolean;
  setLearnOpen: (v: boolean) => void;
  glossaryTerm: string | null;
  showTerm: (k: string) => void;
  toasts: Toast[];
  toast: (text: string, tone?: Toast["tone"]) => void;
  /** GET /auth: run mode, credentials and can_apply. */
  auth: Loadable<AuthInfo>;
  refreshAuth: (refresh?: boolean) => Promise<void>;
  /** Intent ids the Apply step is limited to (null = the whole cart). */
  applyFocus: string[] | null;
  openApply: (ids?: string[] | null) => void;
  run: ApplyRun | null;
  history: ApplyRun[];
  startApply: (intents: Intent[], confirm: ApplyConfirm) => Promise<void>;
  cancelApply: () => void;
  dismissRun: () => void;
  /** Put inverse intents into the cart and open Apply on them. */
  stageUndo: (intents: Intent[]) => void;
  /** The guided "Set up Model Armor in this region" wizard on the Model Armor step. */
  maSetupOpen: boolean;
  openMaSetup: () => void;
  setMaSetupOpen: (v: boolean) => void;
};

const Ctx_ = createContext<Studio | null>(null);
export const useStudio = () => {
  const s = useContext(Ctx_);
  if (!s) throw new Error("useStudio outside provider");
  return s;
};

const DEFAULT_CTX: Ctx = { project: "", region: "", gateway_project: "", ge_app: "", ge_location: "global" };

async function into<T>(set: (f: (p: Loadable<T>) => Loadable<T>) => void, p: Promise<T>) {
  set((s) => ({ ...s, loading: true, error: null }));
  try {
    const data = await p;
    set(() => ({ data, loading: false, error: null }));
  } catch (e) {
    set((s) => ({ ...s, loading: false, error: e instanceof Error ? e.message : String(e) }));
  }
}

export function StudioProvider({ children }: { children: ReactNode }) {
  const [ctx, setCtxState] = useState<Ctx>(() => ({ ...DEFAULT_CTX, ...load<Partial<Ctx>>("studio.ctx", {}) }));
  const [ctxInfo, setCtxInfo] = useState(empty<ContextInfo>);
  const [gateways, setGateways] = useState(empty<GatewaysResp>);
  const [modelArmor, setModelArmor] = useState(empty<ModelArmorResp>);
  const [inventory, setInventory] = useState(empty<Inventory>);
  const [audit, setAudit] = useState(empty<AuditResp>);
  const [syncing, setSyncing] = useState(false);
  const [syncedAt, setSyncedAt] = useState<number | null>(null);
  const [cart, setCart] = useState<Intent[]>(() => load<Intent[]>("studio.cart", []));
  const [step, setStep] = useState<StepN>(() => (load<Partial<Ctx>>("studio.ctx", {}).project ? 1 : 0) as StepN);
  const [draft, setDraft] = useState<Studio["draft"]>(null);
  const [reviewFocus, setReviewFocus] = useState<string | null>(null);
  const [learnOpen, setLearnOpenState] = useState<boolean>(() => load("studio.learn", true));
  const [glossaryTerm, setGlossaryTerm] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [auth, setAuth] = useState(empty<AuthInfo>);
  const [applyFocus, setApplyFocus] = useState<string[] | null>(null);
  const [run, setRun] = useState<ApplyRun | null>(null);
  const [history, setHistory] = useState<ApplyRun[]>(() => {
    try {
      return JSON.parse(sessionStorage.getItem("studio.applyHistory") ?? "[]") as ApplyRun[];
    } catch {
      return [];
    }
  });
  const [maSetupOpen, setMaSetupOpen] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const ctxRef = useRef(ctx);
  ctxRef.current = ctx;

  useEffect(() => {
    try {
      sessionStorage.setItem("studio.applyHistory", JSON.stringify(history.slice(0, 20)));
    } catch {
      /* storage disabled */
    }
  }, [history]);

  const refreshAuth = useCallback(async (refresh = false) => {
    await into(setAuth, api.auth(ctxRef.current, refresh));
  }, []);
  // Fetch /auth on load and whenever the project changes (Sync re-fetches it too).
  useEffect(() => {
    void refreshAuth(false);
  }, [ctx.project, refreshAuth]);

  useEffect(() => save("studio.cart", cart), [cart]);

  const setCtx = useCallback((c: Ctx) => {
    setCtxState(c);
    save("studio.ctx", c);
  }, []);

  const sync = useCallback(async (refresh = true, c?: Ctx) => {
    const cx = c ?? ctxRef.current;
    if (!cx.project || !cx.region) return;
    setSyncing(true);
    await Promise.all([
      into(setCtxInfo, api.context(cx, refresh)),
      into(setGateways, api.gateways(cx, refresh)),
      into(setModelArmor, api.modelArmor(cx, refresh)),
      into(setInventory, api.inventory(cx, refresh)),
      into(setAudit, api.audit(cx, refresh)),
      into(setAuth, api.auth(cx, refresh)),
    ]);
    setSyncing(false);
    setSyncedAt(Date.now());
  }, []);

  useEffect(() => {
    if (ctxRef.current.project) void sync(false);
    else
      api
        .defaults()
        .then((d) => {
          if (ctxRef.current.project || !d.project) return;
          const c = { ...ctxRef.current, project: d.project, region: d.region ?? "" };
          setCtxState(c);
          ctxRef.current = c;
          if (c.region) void sync(false, c);
        })
        .catch(() => undefined);
  }, [sync]);

  const toast = useCallback((text: string, tone?: Toast["tone"]) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-2), { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200);
  }, []);

  const cartRef = useRef(cart);
  cartRef.current = cart;
  const addIntents = useCallback(
    (items: Intent[]) => {
      // Same kind + gateway / engine / source / destination / access / params = the same change: add it once.
      const seen = new Set(cartRef.current.map(intentKey));
      const fresh = items.filter((i) => {
        const k = intentKey(i);
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
      const dupes = items.length - fresh.length;
      if (fresh.length) {
        const next = [...cartRef.current, ...fresh.map((i) => ({ ...i, id: cartRef.current.some((x) => x.id === i.id) ? newId() : i.id || newId() }))];
        cartRef.current = next;
        setCart(next);
      }
      if (!fresh.length) toast(dupes === 1 ? "Already in the cart" : "All of these are already in the cart", "warn");
      else toast((fresh.length === 1 ? "Added to the policy cart" : `Added ${fresh.length} items to the policy cart`) + (dupes ? ` (${dupes} already in the cart)` : ""), "ok");
    },
    [toast],
  );
  const updateIntent = useCallback((id: string, it: Intent) => setCart((c) => c.map((x) => (x.id === id ? { ...it, id } : x))), []);
  const removeIntent = useCallback((id: string) => setCart((c) => c.filter((x) => x.id !== id)), []);
  const duplicateIntent = useCallback(
    (id: string) =>
      setCart((c) => {
        const i = c.findIndex((x) => x.id === id);
        if (i < 0) return c;
        const copy = { ...structuredClone(c[i]), id: newId() };
        return [...c.slice(0, i + 1), copy, ...c.slice(i + 1)];
      }),
    [],
  );
  const clearCart = useCallback(() => setCart([]), []);

  const goto = useCallback((s: StepN) => {
    setStep(s);
    document.querySelector(".center")?.scrollTo({ top: 0 });
  }, []);
  const seq = useRef(0);
  const openBuilder = useCallback<Studio["openBuilder"]>(
    (intent, opts) => {
      setDraft({ intent, editId: opts?.editId, mode: opts?.mode, seq: ++seq.current });
      goto(4);
    },
    [goto],
  );
  const openReview = useCallback(
    (id?: string | null) => {
      setReviewFocus(id ?? null);
      goto(5);
    },
    [goto],
  );
  const setLearnOpen = useCallback((v: boolean) => {
    setLearnOpenState(v);
    save("studio.learn", v);
  }, []);
  const showTerm = useCallback(
    (k: string) => {
      setLearnOpen(true);
      setGlossaryTerm(null);
      requestAnimationFrame(() => setGlossaryTerm(k));
    },
    [setLearnOpen],
  );

  const openApply = useCallback(
    (ids?: string[] | null) => {
      setApplyFocus(ids && ids.length ? ids : null);
      goto(6);
    },
    [goto],
  );

  const startApply = useCallback<Studio["startApply"]>(
    async (intents, confirm) => {
      const cx = ctxRef.current;
      const ac = new AbortController();
      abortRef.current = ac;
      let cur: ApplyRun = {
        id: newId("run"),
        project: cx.project,
        region: cx.region,
        startedAt: Date.now(),
        items: intents.map((intent) => ({ intent, state: "queued", undo: [] })),
        done: false,
      };
      const put = (r: ApplyRun) => {
        cur = r;
        setRun(r);
      };
      put(cur);
      try {
        await api.apply(
          cx,
          intents,
          confirm,
          (e) => {
            if ("type" in e && e.type === "done") {
              put({ ...cur, summary: e.summary });
              return;
            }
            if (!("intent_id" in e)) return;
            const now = Date.now();
            // A polled long-running operation sends repeated "done" + progress events: still running.
            const state = e.state === "done" && e.progress ? "running" : e.state;
            put({
              ...cur,
              items: cur.items.map((it) =>
                it.intent.id !== e.intent_id
                  ? it
                  : {
                      ...it,
                      state,
                      detail: e.detail ?? it.detail,
                      operation: e.operation ?? it.operation,
                      rawError: e.raw_error ?? it.rawError,
                      undo: e.undo ? toList(e.undo) : it.undo,
                      startedAt: it.startedAt ?? now,
                      endedAt: state === "verified" || state === "failed" || state === "skipped" ? now : undefined,
                    },
              ),
            });
          },
          ac.signal,
        );
      } catch (err) {
        const aborted = err instanceof DOMException && err.name === "AbortError";
        put({ ...cur, error: aborted ? "Stopped watching. Changes already sent may still finish in the background; Sync to see the current state." : err instanceof Error ? err.message : String(err) });
      }
      // Anything the stream never finished is reported as unknown rather than silently dropped.
      const final: ApplyRun = {
        ...cur,
        done: true,
        endedAt: Date.now(),
        items: cur.items.map((it) =>
          it.state === "running" || it.state === "done" || it.state === "queued"
            ? { ...it, state: it.state === "queued" ? "skipped" : "failed", detail: it.state === "queued" ? "Not started." : `${it.detail ?? ""} (no final result received; Sync to check)`.trim() }
            : it,
        ),
      };
      put(final);
      abortRef.current = null;
      setHistory((h) => [final, ...h].slice(0, 20));
      const changed = final.items.filter((i) => i.state === "verified" || i.state === "done");
      const finished = new Set(final.items.filter((i) => i.state === "verified" || i.state === "skipped").map((i) => i.intent.id));
      if (finished.size) setCart((c) => c.filter((x) => !finished.has(x.id)));
      setApplyFocus((f) => (f ? f.filter((id) => !finished.has(id)) : f));
      if (changed.length) {
        toast(`Applied ${changed.length} change${changed.length > 1 ? "s" : ""}. Syncing…`, "ok");
        void sync(true);
      }
    },
    [sync, toast],
  );
  const cancelApply = useCallback(() => abortRef.current?.abort(), []);
  const dismissRun = useCallback(() => setRun(null), []);
  const stageUndo = useCallback(
    (intents: Intent[]) => {
      // An undo that is already in the cart (e.g. "enforce" staged from Gateways) isn't staged twice: Apply focuses
      // on the cart item instead.
      const existing: string[] = [];
      const fresh: Intent[] = [];
      for (const i of intents) {
        const same = cartRef.current.find((c) => sameChange(c, i));
        if (same) existing.push(same.id);
        else fresh.push(i);
      }
      const staged = fresh.map((i) => ({ ...structuredClone(i), id: newId("u") }));
      if (staged.length) {
        cartRef.current = [...cartRef.current, ...staged];
        setCart(cartRef.current);
      }
      toast(
        !staged.length
          ? "Already staged in the cart"
          : `${staged.length === 1 ? "Undo staged in the cart" : `${staged.length} undo items staged in the cart`}${existing.length ? ` (${existing.length} already there)` : ""}`,
        "ok",
      );
      setRun(null);
      setApplyFocus([...existing, ...staged.map((i) => i.id)]);
      goto(6);
    },
    [goto, toast],
  );

  const openMaSetup = useCallback(() => {
    setMaSetupOpen(true);
    goto(2);
    requestAnimationFrame(() => document.getElementById("ma-setup")?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }, [goto]);

  const value = useMemo<Studio>(
    () => ({
      ctx, setCtx, ctxInfo, gateways, modelArmor, inventory, audit, syncing, syncedAt, sync,
      cart, addIntents, updateIntent, removeIntent, duplicateIntent, clearCart,
      step, goto, draft, openBuilder, reviewFocus, openReview,
      learnOpen, setLearnOpen, glossaryTerm, showTerm, toasts, toast,
      auth, refreshAuth, applyFocus, openApply, run, history, startApply, cancelApply, dismissRun, stageUndo,
      maSetupOpen, openMaSetup, setMaSetupOpen,
    }),
    [maSetupOpen, openMaSetup, auth, refreshAuth, applyFocus, openApply, run, history, startApply, cancelApply, dismissRun, stageUndo, ctx, setCtx, ctxInfo, gateways, modelArmor, inventory, audit, syncing, syncedAt, sync, cart, addIntents, updateIntent, removeIntent, duplicateIntent, clearCart, step, goto, draft, openBuilder, reviewFocus, openReview, learnOpen, setLearnOpen, glossaryTerm, showTerm, toasts, toast],
  );
  return <Ctx_.Provider value={value}>{children}</Ctx_.Provider>;
}

/** Look up display labels for engines and registry entries from the inventory. */
export function useLookup() {
  const { inventory, gateways } = useStudio();
  return useMemo(() => {
    const inv = inventory.data;
    const engineByName = new Map((inv?.engines ?? []).map((e) => [e.name, e]));
    const engineByPrincipal = new Map((inv?.engines ?? []).map((e) => [e.principal, e]));
    const egress = gateways.data?.gateways.find((g) => g.type === "egress");
    const ingress = gateways.data?.gateways.find((g) => g.type === "ingress");
    return { inv, engineByName, engineByPrincipal, egress, ingress };
  }, [inventory.data, gateways.data]);
}
