// Build step: the guided policy builder (Who → What → How much) with a live preview, IAM anatomy,
// prerequisite checks and a Revoke mode.
import { Tip } from "../components/Tooltip";
import { useEffect, useMemo, useRef, useState } from "react";
import { useLookup, useStudio } from "../store";
import { api } from "../api/client";
import type { AccessMode, Binding, Grant, Intent, RenderItem, SourceType } from "../api/types";
import { Badge, Callout, KindIcon, Load, StepHeader, Tabs, Term } from "../components/ui";
import { ToolBadge, useDestinations } from "./InventoryStep";
import { WarningCallouts } from "./ModelArmorSetup";
import { grantToIntent, grantToModify, revokesGrant } from "../lib/grants";
import { CheckIcon, PlusIcon, RobotIcon, SearchIcon, WarnIcon } from "../components/Icons";
import {
  READ_ONLY_EXPR,
  ROLE,
  conditionFor,
  intentEnglish,
  kindNoun,
  lintExpression,
  newId,
  projectPrincipalSet,
  readOnlyTools,
  validateMember,
} from "../lib/policy";

type DestType = "all" | "a2a" | "runtime" | "mcp" | "api";
const DEST_TYPES: { id: DestType; label: string; tip: string }[] = [
  { id: "all", label: "All", tip: "Show every destination in the Agent Registry for this region." },
  { id: "a2a", label: "A2A agents", tip: "Remote agents called over the Agent2Agent (A2A) protocol, e.g. on Cloud Run." },
  { id: "runtime", label: "Agent Runtime agents", tip: "Agents on Agent Runtime, registered automatically." },
  { id: "mcp", label: "MCP servers", tip: "MCP servers; you can limit access to read-only or specific tools." },
  { id: "api", label: "APIs", tip: "API endpoints registered in Agent Registry (e.g. Google APIs the agent needs)." },
];
function destTypeOf(d: { kind: string; sub: string }): DestType {
  if (d.kind === "mcp_server") return "mcp";
  if (d.kind === "endpoint") return "api";
  return d.sub === "A2A agent" ? "a2a" : "runtime";
}

type Mode = "grant" | "revoke";

function Section({ n, title, sub, done, children }: { n: number; title: string; sub: string; done: boolean; children: React.ReactNode }) {
  return (
    <section className={`card build-sec ${done ? "done" : ""}`} aria-labelledby={`sec-${n}`}>
      <header className="build-sec-head">
        <span className="sec-num">{done ? <CheckIcon size={14} /> : n}</span>
        <div>
          <h2 id={`sec-${n}`}>{title}</h2>
          <p className="muted small">{sub}</p>
        </div>
      </header>
      {children}
    </section>
  );
}

function Choice({ name, checked, onChange, title, desc, badge, disabled, children, label }: { label?: string; name: string; checked: boolean; onChange: () => void; title: React.ReactNode; desc?: React.ReactNode; badge?: React.ReactNode; disabled?: boolean; children?: React.ReactNode }) {
  return (
    <label className={`choice ${checked ? "checked" : ""} ${disabled ? "disabled" : ""}`}>
      <input type="radio" name={name} checked={checked} onChange={onChange} disabled={disabled} aria-label={label ?? (typeof title === "string" ? title : undefined)} />
      <span className="choice-body">
        <span className="choice-title">
          {title} {badge}
        </span>
        {desc && <span className="choice-desc">{desc}</span>}
        {checked && children && <span className="choice-extra" onClick={(e) => e.stopPropagation()}>{children}</span>}
      </span>
    </label>
  );
}

/** Prerequisite / redundancy checks shown as amber chips with an optional "also stage fix", or an intent to stage
 *  instead of this one (`instead`, e.g. a modify of the existing grant). */
type Check = { id: string; tone: "amber" | "info" | "red"; text: React.ReactNode; fix?: Intent; fixLabel?: string; instead?: Intent; insteadLabel?: string; insteadTip?: string };

function useChecks(intent: Intent | null): Check[] {
  const { inventory, cart } = useStudio();
  const { engineByName, engineByPrincipal, egress } = useLookup();
  return useMemo(() => {
    const out: Check[] = [];
    const inv = inventory.data;
    if (!intent || !inv || intent.kind !== "grant" || !intent.source || !intent.destination) return out;
    const src = intent.source;
    const dest = intent.destination;
    if (src.type === "engine" && src.engine) {
      const e = engineByName.get(src.engine);
      if (e && !e.gateways.egress) {
        const staged = cart.some((i) => i.kind === "bind_gateway" && i.engine === e.name && i.gateway?.direction === "egress");
        if (!e.bindable) out.push({ id: "nobind", tone: "red", text: <>{e.display_name} isn't behind an egress gateway and can't be bound ({e.bindable_reason ?? "created before 2026-04-29"}). This grant won't be checked until it is redeployed.</> });
        else if (staged) out.push({ id: "bindstaged", tone: "info", text: <>{e.display_name} will be bound to an egress gateway (already in your cart).</> });
        else
          out.push({
            id: "bind",
            tone: "amber",
            text: <>{e.display_name} isn't behind an egress gateway, so its calls go out directly and this grant is never checked.</>,
            fix: egress ? { id: newId(), kind: "bind_gateway", gateway: { name: egress.name, direction: "egress" }, engine: e.name, engine_label: e.display_name } : undefined,
            fixLabel: egress ? `Also stage: bind to ${egress.id}` : undefined,
          });
      }
    }
    const all = [...inv.agents.map((a) => a.name), ...inv.mcp_servers.map((m) => m.name), ...inv.endpoints.map((x) => x.name)];
    if (!all.includes(dest.name)) out.push({ id: "unreg", tone: "amber", text: <>{dest.label} isn't in the Agent Registry for this region. The gateway can't route to unregistered destinations; register it first.</> });

    const current: Binding[] = inv.access[dest.name] ?? [];
    const cond = conditionFor(intent.access);
    const mine = current.filter((b) => b.member === src.principal && b.role === ROLE);
    if (mine.some((b) => (b.condition?.expression ?? "") === (cond?.expression ?? ""))) out.push({ id: "dup", tone: "info", text: <>This exact grant already exists. Adding it again changes nothing.</> });
    else if (mine.length) {
      // IAM adds bindings rather than replacing them: a grant would sit next to the existing one, which keeps its
      // access. A modify swaps the existing binding (its exact condition) for this access in one change.
      const g: Grant = { ...mine[0], resource: dest.name, resource_kind: dest.kind, resource_label: dest.label };
      out.push({
        id: "replace",
        tone: "amber",
        text: (
          <>
            {src.label} already has {mine[0].condition ? "conditional" : "unconditional"} access here (“{mine[0].english}”){mine.length > 1 ? ` and ${mine.length - 1} more grant${mine.length > 2 ? "s" : ""}` : ""}. IAM adds this grant as a second binding next to it, so the existing access stays as it is.
          </>
        ),
        instead: { ...grantToModify(g, engineByPrincipal, intent.access ?? { mode: "all" }), source: src, destination: dest },
        insteadLabel: "Change the existing grant instead",
        insteadTip: "Stage one change that replaces the existing grant's access with this one (a single IAM update, so there's no moment with both or neither). Nothing changes in Google Cloud until you apply.",
      });
    }
    const broader = current.find((b) => b.role === ROLE && !b.condition && b.member !== src.principal && (b.member.startsWith("principalSet://") || b.member.startsWith("all")) && src.type !== "project_agents");
    if (broader) out.push({ id: "broader", tone: "amber", text: <>An existing broader grant already allows this: “{broader.english}”. Your narrower grant won't restrict it.</> });
    if (intent.access?.mode === "all" && dest.kind === "mcp_server") {
      const d = inv.mcp_servers.find((m) => m.name === dest.name)?.tools.filter((t) => t.destructive) ?? [];
      if (d.length) out.push({ id: "destructive", tone: "amber", text: <>Full access includes destructive tools ({d.map((t) => t.name).join(", ")}). Consider “Read-only by MCP hint”.</> });
    }
    if (src.type === "project_agents") out.push({ id: "broad", tone: "info", text: <>Every agent in the project gets this, including agents created later.</> });
    return out;
  }, [intent, inventory.data, engineByName, engineByPrincipal, egress, cart]);
}

function AnatomyRow({ k, v, meaning, mono = true }: { k: string; v: React.ReactNode; meaning: React.ReactNode; mono?: boolean }) {
  return (
    <div className="anat-row">
      <div className="anat-k">{k}</div>
      <div className="anat-v">
        <div className={mono ? "mono anat-code" : ""}>{v}</div>
        <div className="anat-m">← {meaning}</div>
      </div>
    </div>
  );
}

function Anatomy({ item, intent }: { item: RenderItem | null; intent: Intent }) {
  const cond = conditionFor(intent.access);
  const a = item?.anatomy;
  const condition = a ? a.condition : cond?.expression;
  const hasEmpty = !!condition && condition.includes("''");
  return (
    <div className="anatomy" aria-label="IAM anatomy">
      <div className="anat-title">
        IAM anatomy <span className="muted small">— what will actually be written</span>
      </div>
      <AnatomyRow k="resource" v={a?.resource || `…/iap_web/agentRegistry/${intent.destination?.kind === "mcp_server" ? "mcpServers" : intent.destination?.kind === "endpoint" ? "endpoints" : "agents"}/${intent.destination?.id}`} meaning={<>what is being protected: the registry entry for {intent.destination?.label}</>} />
      <AnatomyRow k="role" v={a?.role || ROLE} meaning={<><Term k="iap-egressor">may send traffic to it through the gateway</Term></>} />
      <AnatomyRow
        k="member"
        v={a?.member || intent.source?.principal}
        meaning={intent.source?.type === "project_agents" ? <Term k="principal-set">every agent in the project</Term> : intent.source?.type === "engine" ? <><Term k="agent-identity">{intent.source.label}'s identity</Term></> : "the principal you entered"}
      />
      <AnatomyRow
        k="condition"
        v={condition || <span className="muted">none</span>}
        meaning={
          condition ? (
            <>
              <Term k="iam-condition">only requests where this is true</Term>
              {hasEmpty && (
                <>
                  . The <span className="mono">''</span> lets <Term k="empty-tool">MCP setup calls</Term> (initialize, tools/list) through: they carry no tool name.
                </>
              )}
            </>
          ) : (
            "no condition: the whole destination"
          )
        }
      />
      {a?.notes && a.notes.length > 0 && (
        <ul className="anat-notes">
          {a.notes.filter((n) => !(hasEmpty && n.includes("''"))).map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ revoke mode
function RevokePicker({ onStage, initial }: { onStage: (i: Intent) => void; initial?: Partial<Intent> }) {
  const { audit } = useStudio();
  const { engineByPrincipal } = useLookup();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<number | null>(null);
  const grants: Grant[] = audit.data?.grants ?? [];
  useEffect(() => {
    if (!initial?.source || !initial.destination) return;
    const idx = grants.findIndex((g) => revokesGrant({ ...initial, kind: "revoke" }, g));
    if (idx >= 0) setSel(idx);
  }, [initial, grants]);
  const toIntent = (g: Grant): Intent => grantToIntent(g, engineByPrincipal, "revoke");
  const shown = grants.map((g, i) => ({ g, i })).filter(({ g }) => !q || `${g.english} ${g.member_label} ${g.resource_label}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <Load l={audit} what="current grants">
      {() => (
        <section className="card">
          <h2 className="card-title">Which access should be removed?</h2>
          <p className="muted small">These are all the egress grants in the project and region. Pick one; you'll get the commands to remove it in Review.</p>
          <label className="search wide">
            <SearchIcon size={16} />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by agent or destination…" aria-label="Filter grants" />
          </label>
          <div className="pick-list" role="radiogroup" aria-label="Grants">
            {shown.map(({ g, i }) => (
              <label key={i} className={`pick ${sel === i ? "checked" : ""}`}>
                <input type="radio" name="revoke" checked={sel === i} onChange={() => setSel(i)} />
                <KindIcon kind={g.resource_kind} />
                <span className="grow">
                  <span className="pick-title">{g.english}</span>
                  <span className="pick-sub">
                    {g.member_label} → {g.resource_label} {g.condition ? <Badge tone="blue">conditional</Badge> : <Badge tone="neutral">unconditional</Badge>}
                  </span>
                </span>
              </label>
            ))}
            {!shown.length && <p className="muted">No grants match.</p>}
          </div>
          <div className="form-actions">
            <Tip tip={sel === null ? "Pick a grant above first." : "Stage removing this grant in the cart. Nothing changes in Google Cloud until you apply."}>
              <button className="btn btn-danger" disabled={sel === null} onClick={() => sel !== null && onStage(toIntent(grants[sel]))}>
                Stage revoke
              </button>
            </Tip>
            {sel !== null && <span className="small">{intentEnglish(toIntent(grants[sel]))}</span>}
          </div>
        </section>
      )}
    </Load>
  );
}

// ------------------------------------------------------------------ main
export function BuilderStep() {
  const { inventory, ctx, ctxInfo, draft, addIntents, updateIntent, openReview, cart } = useStudio();
  const { inv, engineByName } = useLookup();
  const dests = useDestinations();
  const [mode, setMode] = useState<Mode>("grant");
  const [editId, setEditId] = useState<string | undefined>();
  const [srcType, setSrcType] = useState<SourceType>("engine");
  const [engine, setEngine] = useState("");
  const [custom, setCustom] = useState("");
  const [destName, setDestName] = useState("");
  const [dq, setDq] = useState("");
  const [dtype, setDtype] = useState<DestType>("all");
  const [access, setAccess] = useState<AccessMode>("all");
  const [tools, setTools] = useState<string[]>([]);
  const [expr, setExpr] = useState(READ_ONLY_EXPR);
  const [render, setRender] = useState<RenderItem | null>(null);
  const [renderErr, setRenderErr] = useState<string | null>(null);
  const [extraFixes, setExtraFixes] = useState<Intent[]>([]);
  const lastSeq = useRef(0);

  // Prefill from "Build a policy for this", audit "Edit in builder", or cart "Edit".
  useEffect(() => {
    if (!draft || draft.seq === lastSeq.current) return;
    lastSeq.current = draft.seq;
    const i = draft.intent;
    setMode(draft.mode ?? (i.kind === "revoke" ? "revoke" : "grant"));
    setEditId(draft.editId);
    setExtraFixes([]);
    if (i.source) {
      setSrcType(i.source.type);
      if (i.source.type === "engine") setEngine(i.source.engine ?? "");
      if (i.source.type === "custom") setCustom(i.source.principal);
    }
    if (i.destination) {
      setDestName(i.destination.name);
      setDq("");
    } else if (i.source) setDestName("");
    setAccess(i.access?.mode ?? (i.destination?.kind === "mcp_server" ? "read_only_hint" : "all"));
    setTools(i.access?.tools ?? []);
    setExpr(i.access?.expression ?? READ_ONLY_EXPR);
  }, [draft]);

  const dest = dests.find((d) => d.name === destName);
  const mcp = dest?.kind === "mcp_server" ? inv?.mcp_servers.find((m) => m.name === dest.name) : undefined;
  const eng = engineByName.get(engine);
  const projectSet = projectPrincipalSet(inv?.engines[0]?.principal, ctxInfo.data?.project_number);
  const customErr = srcType === "custom" ? validateMember(custom) : null;
  const effMode: AccessMode = dest && dest.kind !== "mcp_server" ? "all" : access;
  const lint = effMode === "custom" ? lintExpression(expr) : [];

  const source: Intent["source"] | undefined =
    srcType === "engine" && eng
      ? { type: "engine", principal: eng.principal, label: eng.display_name, engine: eng.name }
      : srcType === "project_agents"
        ? { type: "project_agents", principal: projectSet, label: "All agents in this project" }
        : srcType === "custom" && !customErr
          ? { type: "custom", principal: custom.trim(), label: custom.trim().replace(/^(user|group|serviceAccount|domain):/, "") }
          : undefined;
  const howDone = effMode === "all" || effMode === "read_only_hint" || (effMode === "tools" && tools.length > 0) || (effMode === "custom" && expr.trim().length > 0);
  const intent: Intent | null =
    source && dest && howDone
      ? {
          id: editId ?? "preview",
          kind: "grant",
          source,
          destination: { kind: dest.kind, id: dest.id, name: dest.name, label: dest.label },
          access: effMode === "tools" ? { mode: "tools", tools } : effMode === "custom" ? { mode: "custom", expression: expr.trim() } : { mode: effMode },
        }
      : null;
  const intentKey = JSON.stringify(intent);
  const checks = useChecks(intent);

  // Live preview from POST /render (debounced); the local sentence shows instantly meanwhile.
  useEffect(() => {
    setRenderErr(null);
    if (!intent) {
      setRender(null);
      return;
    }
    let live = true;
    const t = setTimeout(() => {
      api
        .render(ctx, [intent])
        .then((r) => live && setRender(r.items[0] ?? null))
        .catch((e) => live && setRenderErr(e instanceof Error ? e.message : String(e)));
    }, 250);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intentKey, ctx]);

  const resetWhat = () => {
    setDestName("");
    setDq("");
    setAccess("all");
    setTools([]);
    setExpr(READ_ONLY_EXPR);
    setExtraFixes([]);
    setEditId(undefined);
  };

  const commit = (another: boolean, staged: Intent | null = intent) => {
    if (!staged) return;
    const finalIntent = { ...staged, id: editId ?? newId() };
    if (editId && cart.some((c) => c.id === editId)) {
      updateIntent(editId, finalIntent);
      if (extraFixes.length) addIntents(extraFixes);
    } else addIntents([...extraFixes, finalIntent]);
    if (another) {
      resetWhat();
      document.querySelector(".center")?.scrollTo({ top: 0, behavior: "smooth" });
    } else {
      resetWhat();
      openReview(finalIntent.id);
    }
  };

  // Name filter first, then the type filter; counts on the type buttons reflect the name filter.
  const byName = dests.filter((d) => !dq || `${d.label} ${d.id} ${d.name} ${d.sub}`.toLowerCase().includes(dq.toLowerCase()));
  const typeCounts = Object.fromEntries(DEST_TYPES.map((t) => [t.id, byName.filter((d) => destTypeOf(d) === t.id || t.id === "all").length])) as Record<DestType, number>;
  const filteredDests = byName.filter((d) => dtype === "all" || destTypeOf(d) === dtype);
  const showAllEndpoints = !!dq || dtype === "api";
  const grouped = (["agent", "mcp_server", "endpoint"] as const).map((k) => ({ k, items: filteredDests.filter((d) => d.kind === k) }));

  return (
    <>
      <StepHeader
        title={mode === "grant" ? "Build a policy" : "Remove access"}
        lead={
          mode === "grant" ? (
            <>Answer three questions: <b>who</b> is calling, <b>what</b> they call, and <b>how much</b> of it they may use. The preview shows exactly what will be written.</>
          ) : (
            <>Pick an existing grant to remove. It's staged in the cart like everything else.</>
          )
        }
        actions={
          <Tabs<Mode>
            label="Builder mode"
            value={mode}
            onChange={(m) => {
              setMode(m);
              setEditId(undefined);
            }}
            items={[
              { id: "grant", label: "Grant access" },
              { id: "revoke", label: "Revoke…" },
            ]}
          />
        }
      />
      {editId && cart.some((c) => c.id === editId) && (
        <Callout tone="info" title="Editing a staged item">
          Changes replace the item in your cart.{" "}
          <Tip tip="Leave the staged item as it is and clear the builder.">
            <button className="link-btn" onClick={resetWhat}>
              Stop editing
            </button>
          </Tip>
        </Callout>
      )}
      {mode === "revoke" ? (
        <RevokePicker
          initial={draft?.mode === "revoke" ? draft.intent : undefined}
          onStage={(i) => {
            if (editId && cart.some((c) => c.id === editId)) updateIntent(editId, { ...i, id: editId });
            else addIntents([i]);
            setEditId(undefined);
          }}
        />
      ) : (
        <Load l={inventory} what="the inventory">
          {(invd) => (
            <div className="builder">
              <Section n={1} title="Who is calling?" sub="The agent whose outbound calls this allows." done={!!source}>
                <div className="choices">
                  <Choice name="src" checked={srcType === "engine"} onChange={() => setSrcType("engine")} title="One agent" desc={<>Uses that agent's <Term k="agent-identity">Agent Identity</Term>. Recommended.</>}>
                    <select value={engine} onChange={(e) => setEngine(e.target.value)} aria-label="Agent">
                      <option value="">Choose an Agent Runtime agent…</option>
                      {invd.engines.map((e) => (
                        <option key={e.name} value={e.name}>
                          {e.display_name}
                          {e.gateways.egress ? "" : " — not behind an egress gateway"}
                        </option>
                      ))}
                    </select>
                    {eng && (
                      <div className="principal-mini">
                        <RobotIcon size={14} /> <span className="mono tiny">{eng.principal}</span>
                      </div>
                    )}
                  </Choice>
                  <Choice name="src" checked={srcType === "project_agents"} onChange={() => setSrcType("project_agents")} title="All agents in this project" desc={<>A <Term k="principal-set">principalSet</Term> that includes future agents too. Good for shared things like Google APIs.</>} />
                  <Choice name="src" checked={srcType === "custom"} onChange={() => setSrcType("custom")} title="Custom principal" desc="Advanced: paste a principal://, principalSet://, serviceAccount:, user: or group: member.">
                    <input value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="principal://agents.global.org-…/reasoningEngines/…" aria-label="Custom principal" aria-invalid={!!customErr && !!custom} spellCheck={false} />
                    {custom && customErr && <div className="field-error small">{customErr}</div>}
                  </Choice>
                </div>
              </Section>

              <Section n={2} title="What may it call?" sub="A destination from the Agent Registry." done={!!dest}>
                {dest ? (
                  <div className="picked">
                    <KindIcon kind={dest.kind} size={18} />
                    <div className="grow">
                      <b>{dest.label}</b> <span className="muted small">· {dest.kind === "endpoint" ? `${kindNoun(dest.kind)} · ${dest.sub}` : dest.sub}</span>
                    </div>
                    <button className="btn btn-small btn-text" onClick={() => setDestName("")}>
                      Change
                    </button>
                  </div>
                ) : (
                  <>
                    <label className="search wide">
                      <SearchIcon size={16} />
                      <input value={dq} onChange={(e) => setDq(e.target.value)} placeholder="Filter by name…" aria-label="Filter destinations by name" autoFocus={!!source} />
                      {dq && (
                        <button className="search-clear" onClick={() => setDq("")} aria-label="Clear name filter">
                          ×
                        </button>
                      )}
                    </label>
                    <div className="type-filters" role="group" aria-label="Filter destinations by type">
                      {DEST_TYPES.map((t) => (
                        <Tip key={t.id} tip={t.tip}>
                          <button
                            className={`type-filter${dtype === t.id ? " on" : ""}`}
                            aria-pressed={dtype === t.id}
                            disabled={t.id !== "all" && typeCounts[t.id] === 0 && dtype !== t.id}
                            onClick={() => setDtype(t.id)}
                          >
                            {t.label} <span className="type-count">{typeCounts[t.id]}</span>
                          </button>
                        </Tip>
                      ))}
                    </div>
                    <div className="dest-list">
                      {grouped.map(({ k, items }) =>
                        items.length ? (
                          <div key={k} className="dest-group">
                            <div className="dest-group-title">{k === "agent" ? "Agents" : k === "mcp_server" ? "MCP servers" : "API endpoints"}</div>
                            {(k === "endpoint" && !showAllEndpoints ? items.slice(0, 5) : items).map((d) => (
                              <button
                                key={d.name}
                                className="dest"
                                onClick={() => {
                                  setDestName(d.name);
                                  setAccess(d.kind === "mcp_server" ? "read_only_hint" : "all");
                                  setTools([]);
                                }}
                              >
                                <KindIcon kind={d.kind} />
                                <span className="grow">
                                  <span className="dest-title">{d.label}</span>
                                  <span className="dest-sub">{d.sub}</span>
                                </span>
                                <span className="muted tiny">{(invd.access[d.name] ?? []).length} grants</span>
                              </button>
                            ))}
                            {k === "endpoint" && !showAllEndpoints && items.length > 5 && (
                              <button className="btn btn-small btn-text dest-more" onClick={() => setDtype("api")}>
                                + {items.length - 5} more: show all APIs
                              </button>
                            )}
                          </div>
                        ) : null,
                      )}
                      {!filteredDests.length && (
                        <p className="muted">
                          No {dtype === "all" ? "destinations" : DEST_TYPES.find((t) => t.id === dtype)!.label} {dq ? <>match “{dq}”</> : "in this region"}.{" "}
                          {(dq || dtype !== "all") && (
                            <button className="btn btn-small btn-text" onClick={() => { setDq(""); setDtype("all"); }}>
                              Clear filters
                            </button>
                          )}
                        </p>
                      )}
                    </div>
                  </>
                )}
              </Section>

              <Section n={3} title="How much of it?" sub={dest?.kind === "mcp_server" ? "MCP servers can be limited to some of their tools." : "A2A agents and APIs are all-or-nothing."} done={!!dest && howDone}>
                {!dest ? (
                  <p className="muted">Pick a destination first.</p>
                ) : dest.kind !== "mcp_server" ? (
                  <div className="choices">
                    <Choice name="how" checked onChange={() => undefined} title="Full access" desc={`The gateway checks who calls ${dest.label}, not which ${dest.kind === "agent" ? "skill" : "path"} they use, so access is all or nothing.`} />
                  </div>
                ) : (
                  <div className="choices">
                    <Choice name="how" checked={access === "read_only_hint"} onChange={() => setAccess("read_only_hint")} title="Read-only tools (by MCP hint)" badge={<Badge tone="green">Recommended</Badge>} desc={<>Allows tools the server marks <Term k="mcp-hints">readOnlyHint</Term>. New read-only tools are covered automatically; new write tools are not.</>}>
                      <div className="tool-preview">
                        Today that's: {readOnlyTools(mcp).map((t) => <span key={t} className="mono-chip">{t}</span>)}
                      </div>
                    </Choice>
                    <Choice name="how" checked={access === "tools"} onChange={() => setAccess("tools")} title="Specific tools" desc="Pick tools by name. Tools added later are not included.">
                      {mcp && (
                        <div className="tool-check">
                          <div className="tool-check-bar">
                            <Tip tip="Tick every tool this MCP server marks readOnlyHint.">
                              <button type="button" className="link-btn" onClick={() => setTools(readOnlyTools(mcp))}>
                                Select all read-only
                              </button>
                            </Tip>
                            <Tip tip="Untick every tool.">
                              <button type="button" className="link-btn" onClick={() => setTools([])}>
                                Clear
                              </button>
                            </Tip>
                            <span className="muted small">{tools.length} selected</span>
                          </div>
                          {mcp.tools.map((t) => (
                            <label key={t.name} className="tool-row">
                              <input type="checkbox" checked={tools.includes(t.name)} onChange={(e) => setTools(e.target.checked ? [...tools, t.name] : tools.filter((x) => x !== t.name))} />
                              <span className="mono small">{t.name}</span>
                              <span className="muted small grow">{t.description}</span>
                              <ToolBadge t={t} />
                            </label>
                          ))}
                        </div>
                      )}
                    </Choice>
                    <Choice name="how" checked={access === "all"} onChange={() => setAccess("all")} title="All tools" desc="Everything the server offers, including write and destructive tools." />
                    <Choice name="how" checked={access === "custom"} onChange={() => setAccess("custom")} title="Custom expression" badge={<Badge tone="neutral">Advanced</Badge>} desc={<>Write your own <Term k="iam-condition">IAM condition</Term> (CEL).</>}>
                      <textarea className="mono expr" rows={4} value={expr} onChange={(e) => setExpr(e.target.value)} spellCheck={false} aria-label="Custom condition" />
                      {lint.length > 0 ? (
                        <ul className="lint">
                          {lint.map((l) => (
                            <li key={l}>
                              <WarnIcon size={13} /> {l}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <div className="small ok-text">
                          <CheckIcon size={13} /> Looks well-formed. IAM validates it for real when it's applied.
                        </div>
                      )}
                      <div className="muted tiny">
                        Attributes: <span className="mono">iap.googleapis.com/mcp.toolName</span>, <span className="mono">iap.googleapis.com/mcp.tool.isReadOnly</span>
                      </div>
                    </Choice>
                  </div>
                )}
              </Section>

              <section className="card preview" aria-live="polite">
                <div className="preview-label">Preview</div>
                {intent ? (
                  <>
                    <p className="preview-sentence">{render?.english ?? intentEnglish(intent)}</p>
                    {checks.length > 0 && (
                      <div className="checks">
                        {checks.map((c) => {
                          const added = c.fix && extraFixes.some((f) => f.kind === c.fix!.kind && f.engine === c.fix!.engine);
                          return (
                            <div key={c.id} className={`check-chip chip-${c.tone}`}>
                              <WarnIcon size={14} />
                              <span className="grow">{c.text}</span>
                              {c.instead && (
                                <Tip tip={c.insteadTip ?? "Stage this instead."}>
                                  <button className="btn btn-small btn-outline" onClick={() => commit(false, c.instead!)}>
                                    {c.insteadLabel ?? "Stage this instead"}
                                  </button>
                                </Tip>
                              )}
                              {c.fix &&
                                (added ? (
                                  <Badge tone="green">fix will be staged</Badge>
                                ) : (
                                  <Tip tip="Also stage this fix when you add the policy to the cart. Nothing changes in Google Cloud until you apply.">
                                    <button className="btn btn-small btn-outline" onClick={() => setExtraFixes([...extraFixes, c.fix!])}>
                                      {c.fixLabel ?? "Also stage fix"}
                                    </button>
                                  </Tip>
                                ))}
                            </div>
                          );
                        })}
                      </div>
                    )}
                    <Anatomy item={render} intent={intent} />
                    <WarningCallouts warnings={render?.warnings.filter((w) => !/egress gateway|destructive/i.test(w))} />
                    {renderErr && <Callout tone="warn" title="Couldn't render on the server; showing a local preview">{renderErr}</Callout>}
                  </>
                ) : (
                  <p className="preview-sentence muted">
                    {!source ? "Choose who is calling (1)…" : !dest ? `${source.label} can call… (choose a destination)` : "Choose at least one tool…"}
                  </p>
                )}
                <div className="preview-actions">
                  <Tip
                    tip={
                      !intent
                        ? "Answer the questions above first."
                        : lint.some((l) => /unbalanced|not closed|empty/.test(l))
                          ? "Fix the condition expression first."
                          : `${editId && cart.some((c) => c.id === editId) ? "Replace the staged item with this policy" : "Stage this policy in the cart"}${extraFixes.length ? ` plus ${extraFixes.length} fix` : ""}, then open Review & output. Nothing changes in Google Cloud until you apply.`
                    }
                  >
                    <button className="btn btn-primary" disabled={!intent || lint.some((l) => /unbalanced|not closed|empty/.test(l))} onClick={() => commit(false)}>
                      {editId && cart.some((c) => c.id === editId) ? "Save changes" : "Add to cart"}
                      {extraFixes.length > 0 && ` (+${extraFixes.length} fix)`}
                    </button>
                  </Tip>
                  <Tip tip={intent ? "Stage this policy in the cart and start a new one, keeping who is calling. Nothing changes in Google Cloud until you apply." : "Answer the questions above first."}>
                    <button className="btn btn-tonal" disabled={!intent} onClick={() => commit(true)}>
                      <PlusIcon size={16} /> Add & build another
                    </button>
                  </Tip>
                  <span className="muted small">Nothing changes in {ctx.project} until you run the generated commands.</span>
                </div>
              </section>
            </div>
          )}
        </Load>
      )}
    </>
  );
}
