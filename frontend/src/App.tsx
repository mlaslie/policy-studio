// Shell: top bar (with the policy cart and the settling chip), stepper, current step, collapsible/resizable Learn rail, toasts.
import { Suspense, lazy, useEffect, useState, type CSSProperties } from "react";
import { STEPS, stepN, useStudio, type StepKey } from "./store";
import { IS_MOCK } from "./api/client";
import { ago } from "./lib/util";
import { mapBadge } from "./lib/mapBadge";
import { CartButton } from "./panels/Cart";
import { SettlingChip } from "./components/Settling";
import { LearnPanel, useRailWidth } from "./panels/Learn";
import { Tip } from "./components/Tooltip";
import { ContextIcon, LockIcon, RefreshIcon, ShieldIcon, CheckIcon, WarnIcon } from "./components/Icons";
import { ContextStep } from "./steps/ContextStep";
import { GatewaysStep } from "./steps/GatewaysStep";
import { ModelArmorStep } from "./steps/ModelArmorStep";
import { InventoryStep } from "./steps/InventoryStep";
import { BuilderStep } from "./steps/BuilderStep";
import { ReviewStep } from "./steps/ReviewStep";
import { ApplyStep } from "./steps/ApplyStep";
import { ModeBadge, useApplyGate } from "./components/Mode";
import { AuditStep } from "./steps/AuditStep";
import { Spinner } from "./components/ui";

// The map (React Flow and the map code, later) is its own chunk: the first load stays the same.
const MapStep = lazy(() => import("./map/MapStep"));

function TopBar() {
  const { ctx, goto, sync, syncing, syncedAt } = useStudio();
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-logo" aria-hidden="true">
          <ShieldIcon size={20} />
        </span>
        <div>
          <div className="brand-title">Policy Studio</div>
          <div className="brand-sub">Agent Gateway · Model Armor · Agent Registry</div>
        </div>
      </div>
      <div className="topbar-right">
        {IS_MOCK && (
          <Tip tip="Running with built-in sample data (npm run dev:mock). No backend is called." placement="bottom">
            <span className="mock-chip">
              MOCK DATA
            </span>
          </Tip>
        )}
        <ModeBadge onClick={() => goto("context")} />
        <Tip tip="Change the project and region every step reads from." placement="bottom">
        <button className="ctx-chip" onClick={() => goto("context")}>
          <ContextIcon size={15} />
          {ctx.project ? (
            <>
              <span className="mono">{ctx.project}</span>
              <span className="sep">·</span>
              <span className="mono">{ctx.region || "no region"}</span>
            </>
          ) : (
            <span>Set project…</span>
          )}
        </button>
        </Tip>
        <Tip
          placement="bottom"
          tip={`Re-read gateways, Model Armor, Agent Registry and IAM from Google Cloud (bypasses the 30-second cache).${!ctx.project ? " Unavailable: set a project first." : syncing ? " Sync is already running." : ""}`}
        >
        <button className="btn btn-tonal sync-btn" onClick={() => sync(true)} disabled={syncing || !ctx.project}>
          <RefreshIcon size={16} className={syncing ? "spin" : ""} />
          <span>{syncing ? "Syncing…" : "Sync"}</span>
          <span className="sync-ago">{syncing ? "" : `synced ${ago(syncedAt, now)}`}</span>
        </button>
        </Tip>
        <SettlingChip />
        <CartButton />
      </div>
    </header>
  );
}

function useStepBadges(): Partial<Record<StepKey, { text: string; tone: string; title?: string }>> {
  const { ctxInfo, gateways, modelArmor, inventory, audit, cart } = useStudio();
  const b: Partial<Record<StepKey, { text: string; tone: string; title?: string }>> = {};
  const ci = ctxInfo.data;
  if (ctxInfo.error) b.context = { text: "!", tone: "red", title: "Context check failed" };
  else if (ci) {
    const miss = ci.permissions.filter((p) => p.granted === false && !p.write).length + Object.values(ci.apis).filter((v) => !v).length;
    b.context = miss ? { text: `${miss}`, tone: "amber", title: `${miss} missing API or permission` } : { text: "✓", tone: "green", title: "All checks passed" };
  }
  if (gateways.data) b.gateways = { text: `${gateways.data.gateways.length}`, tone: "neutral", title: "Gateways in this region" };
  if (modelArmor.data) {
    const on = modelArmor.data.gateways.filter((g) => g.enabled).length;
    b["model-armor"] = { text: `${on}/${modelArmor.data.gateways.length}`, tone: on === modelArmor.data.gateways.length ? "green" : "amber", title: "Gateways with Model Armor on" };
  }
  if (inventory.data) {
    const i = inventory.data;
    b.inventory = { text: `${i.agents.filter((a) => a.kind === "a2a").length + i.mcp_servers.length + i.endpoints.length}`, tone: "neutral", title: "Registered destinations" };
  }
  const onMap = mapBadge(cart);
  if (onMap) b.map = onMap;
  if (cart.length) b.review = { text: `${cart.length}`, tone: "blue", title: "Staged items" };
  if (audit.data) {
    const high = audit.data.findings.filter((f) => f.severity === "high").length;
    const n = audit.data.findings.filter((f) => f.severity !== "info").length;
    b.audit = n ? { text: `${n}`, tone: high ? "red" : "amber", title: `${n} findings (${high} high)` } : { text: "✓", tone: "green" };
  }
  return b;
}

function Stepper() {
  const { step, goto, run } = useStudio();
  const badges = useStepBadges();
  const gate = useApplyGate();
  if (run && !run.done) badges.apply = { text: "…", tone: "blue", title: "Applying now" };
  else if (gate.auth && !gate.canApply) badges.apply = { text: "lock", tone: gate.generate ? "blue" : "amber", title: gate.reason ?? "" };
  return (
    <nav className="stepper" aria-label="Steps">
      <ol>
        {STEPS.map((s, n) => {
          const badge = badges[s.key];
          return (
            <li key={s.key}>
              <button
                className={`step ${step === s.key ? "current" : ""}`}
                aria-current={step === s.key ? "step" : undefined}
                aria-label={`Step ${n}: ${s.title}${badge?.title ? `, ${badge.title}` : ""}`}
                onClick={() => goto(s.key)}
              >
                <span className="step-num">{n}</span>
                <span className="step-text">
                  <span className="step-title">{s.title}</span>
                  <span className="step-sub">{s.sub}</span>
                </span>
                {badge && (
                  <span className={`step-badge badge-${badge.tone}`} title={badge.title}>
                    {badge.text === "✓" ? <CheckIcon size={12} /> : badge.text === "!" ? <WarnIcon size={12} /> : badge.text === "lock" ? <LockIcon size={11} /> : badge.text}
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ol>
      <p className="stepper-foot">
        Step {stepN("map")} shows who can reach what. Steps {stepN("gateways")}–{stepN("inventory")} show the details. Step {stepN("build")} builds a change. Step {stepN("review")} turns your cart into commands. Step {stepN("apply")} applies them (when running locally).
      </p>
    </nav>
  );
}

function Toasts() {
  const { toasts } = useStudio();
  return (
    <div className="toasts" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast glass toast-${t.tone ?? "info"}`}>
          {t.tone === "ok" && <CheckIcon size={16} />}
          {t.text}
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const { step } = useStudio();
  const rail = useRailWidth();
  return (
    <div className="app">
      <TopBar />
      <div className="layout" style={{ "--rail-w": `${rail.effective}px` } as CSSProperties}>
        <Stepper />
        <main className={`center ${step === "map" ? "center-wide" : ""}`} id="main">
          <div className="center-inner">
            {step === "context" && <ContextStep />}
            {step === "map" && (
              <Suspense fallback={<Spinner label="Loading the policy map…" />}>
                <MapStep />
              </Suspense>
            )}
            {step === "gateways" && <GatewaysStep />}
            {step === "model-armor" && <ModelArmorStep />}
            {step === "inventory" && <InventoryStep />}
            {step === "build" && <BuilderStep />}
            {step === "review" && <ReviewStep />}
            {step === "apply" && <ApplyStep />}
            {step === "audit" && <AuditStep />}
          </div>
        </main>
        <LearnPanel width={rail.width} setWidth={rail.setWidth} />
      </div>
      <Toasts />
    </div>
  );
}
