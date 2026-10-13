// Build step: the guided policy builder (Who → What → How much) with a live preview, IAM anatomy,
// prerequisite checks and a Revoke mode. When the source already holds grants on the destination it works in "change
// existing access" mode (lib/existing.ts): one modify replaces them all (or a revoke / the remove-all form removes
// them). Add to cart opens a preview first (preview/PreviewDialog.tsx, lazy-loaded; preview/flow.ts).
import { Tip } from "../components/Tooltip";
import { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import { useLookup, useStudio } from "../store";
import { api } from "../api/client";
import type { AccessMode, Grant, Intent, RenderItem, SourceType } from "../api/types";
import { Badge, Callout, KindIcon, Load, Spinner, StepHeader, Tabs, Term } from "../components/ui";
import { useDestinations } from "./InventoryStep";
import { WarningCallouts } from "./ModelArmorSetup";
import { grantToIntent, revokesGrant } from "../lib/grants";
import { useChecks } from "../lib/checks";
import { AccessChooser, Choice, blocking, draftLint, type ChooserExtras } from "../components/AccessChooser";
import { CheckIcon, PlusIcon, RobotIcon, SearchIcon, WarnIcon } from "../components/Icons";
import { READ_ONLY_EXPR, ROLE, accessFromCondition, accessTos, conditionFor, intentEnglish, kindNoun, newId, projectPrincipalSet, removesAll, validateMember } from "../lib/policy";
import { buildModeOf, changeIntent, existingFor, initialChoice, inheritedLabel, isSame, lockedTools, modeOptions, targetOf, toolNote, toolsToday, usesHint, type BuildChoice, type BuildMode } from "../lib/existing";
import { focusForGrant } from "../map/focus";
import { approve as approvePreview, cancel as cancelPreview, openPreview, type PreviewState } from "../preview/flow";

const PreviewDialog = lazy(() => import("../preview/PreviewDialog"));

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
  const { inventory, ctx, ctxInfo, draft, addIntents, updateIntent, openReview, openMap, cart } = useStudio();
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
  const [remove, setRemove] = useState(false);
  const [preview, setPreview] = useState<PreviewState>(null);
  const lastSeq = useRef(0);
  /** The draft's source and destination, and whether it edits a cart item: its access stands (see the pair effect). */
  const prefill = useRef<{ key: string; editing: boolean } | null>(null);
  const lastPair = useRef<{ key: string; own: string; mode: BuildMode } | null>(null);

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
    // A staged modify's new access (the remove-all form: no tool / "Remove access"); a custom expression that is one
    // of the known forms (an exact one from a grant) is shown as that form.
    const acc = i.kind === "modify" ? accessTos(i)[0] : i.access;
    const a = acc?.mode === "custom" ? accessFromCondition(acc.expression) : acc;
    const gone = i.kind === "modify" && removesAll(i as Intent);
    setAccess(gone ? (i.destination?.kind === "mcp_server" ? "tools" : "all") : (a?.mode ?? (i.destination?.kind === "mcp_server" ? "read_only_hint" : "all")));
    setTools(gone ? [] : (a?.tools ?? []));
    setExpr(a?.mode === "custom" ? (a.expression ?? "") : READ_ONLY_EXPR);
    setRemove(gone && i.destination?.kind !== "mcp_server");
    prefill.current = i.source && i.destination ? { key: `${i.source.principal}|${i.destination.name}`, editing: !!draft.editId } : null;
  }, [draft]);

  const dest = dests.find((d) => d.name === destName);
  const mcp = dest?.kind === "mcp_server" ? inv?.mcp_servers.find((m) => m.name === dest.name) : undefined;
  const eng = engineByName.get(engine);
  const projectSet = projectPrincipalSet(inv?.engines[0]?.principal, ctxInfo.data?.project_number);
  const customErr = srcType === "custom" ? validateMember(custom) : null;

  const source: Intent["source"] | undefined =
    srcType === "engine" && eng
      ? { type: "engine", principal: eng.principal, label: eng.display_name, engine: eng.name }
      : srcType === "project_agents"
        ? { type: "project_agents", principal: projectSet, label: "All agents in this project" }
        : srcType === "custom" && !customErr
          ? { type: "custom", principal: custom.trim(), label: custom.trim().replace(/^(user|group|serviceAccount|domain):/, "") }
          : undefined;
  // ---------- change existing access: what the source holds on the destination today ----------
  const ex = useMemo(() => existingFor(inv, source?.principal, dest?.name), [inv, source?.principal, dest?.name]);
  const bmode: BuildMode = source && dest ? buildModeOf(ex) : "new";
  const change = bmode === "change";
  const today = useMemo(() => toolsToday(mcp, ex), [mcp, ex]);
  const locked = useMemo(() => lockedTools(today), [today]);
  const initial = useMemo(() => (dest ? initialChoice(dest.kind, ex, mcp) : null), [dest, ex, mcp]);
  const choice: BuildChoice = { mode: access, tools, expr, remove };
  const applyChoice = (c: BuildChoice) => {
    setAccess(c.mode);
    setTools(c.tools);
    setExpr(c.expr);
    setRemove(!!c.remove);
  };
  // A new source / destination pair (or a Sync that changes its grants) starts from its initial choice: today's access
  // in change mode, the default for a new grant (read-only hint on MCP servers). A draft's access stands, except a
  // non-edit draft in change mode (Audit's "Edit" of one grant among several: today's access, all of it).
  const pairKey = source && dest ? `${source.principal}|${dest.name}` : "";
  const ownKey = ex.own.map((b) => b.condition?.expression ?? "").join("\n");
  useEffect(() => {
    if (!pairKey || !initial) {
      if (!pairKey) lastPair.current = null;
      return;
    }
    const prev = lastPair.current;
    lastPair.current = { key: pairKey, own: ownKey, mode: bmode };
    if (prev && prev.key === pairKey && prev.own === ownKey) return;
    const pf = prefill.current;
    prefill.current = null;
    if (pf && pf.key === pairKey && (bmode === "new" || pf.editing)) return;
    applyChoice(initial);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pairKey, ownKey, bmode]);

  const lint = dest ? draftLint({ mode: access, tools, expr, remove }, dest.kind, change) : [];
  const target = source && dest ? targetOf(choice, dest.kind, bmode, new Set(locked.keys())) : null;
  const intent: Intent | null =
    source && dest ? changeIntent({ id: editId ?? "preview", source, destination: { kind: dest.kind, id: dest.id, name: dest.name, label: dest.label }, own: ex.own, target }) : null;
  const same = change && isSame(ex.own, target);
  const intentKey = JSON.stringify(intent);
  // Prerequisite checks read a grant: in change mode, the grant-shaped version of the new access (the "already
  // exists" / "change the existing grant instead" checks don't apply: this is that change).
  const checkIntent: Intent | null = intent?.kind === "grant" ? intent : source && dest && target && target !== "remove" ? { id: "check", kind: "grant", source, destination: { kind: dest.kind, id: dest.id, name: dest.name, label: dest.label }, access: target } : null;
  const checks = useChecks(checkIntent).filter((c) => !change || (c.id !== "dup" && c.id !== "replace"));

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
    setRemove(false);
    setExtraFixes([]);
    setEditId(undefined);
  };
  const editing = !!editId && cart.some((c) => c.id === editId);

  // ---------- the Add to cart preview (preview/flow.ts) ----------
  const onApprove = () => {
    if (!preview) return;
    const { effect } = approvePreview(preview, () => newId());
    setPreview(null);
    if (effect.kind !== "stage") return;
    if (effect.replace) {
      updateIntent(effect.replace.id, effect.replace.intent);
      if (effect.intents.length) addIntents(effect.intents);
    } else addIntents(effect.intents);
    resetWhat();
    if (effect.another) document.querySelector(".center")?.scrollTo({ top: 0, behavior: "smooth" });
    else openReview(effect.focus);
  };
  const onCancel = () => {
    if (!initial) return setPreview(null);
    const { effect } = cancelPreview(initial);
    setPreview(null);
    if (effect.kind === "reset") {
      applyChoice(effect.choice);
      setExtraFixes([]);
    }
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

  // The chooser in change mode: the choices offered, a note per tool (which own grant allows it today), inherited tools
  // locked (with a link to their grant), the read-only hint's note, and today's access on other destinations.
  const chooserExtras: ChooserExtras | undefined =
    dest && source && (change || locked.size)
      ? {
          modes: change ? modeOptions(dest.kind, bmode, ex) : undefined,
          toolNotes: change ? Object.fromEntries(today.flatMap((t) => (toolNote(t) ? [[t.name, toolNote(t)!]] : []))) : undefined,
          locked: new Map(
            [...locked].map(([t, h]) => [
              t,
              {
                text: `allowed by ${inheritedLabel(h)}${h.via === "group" ? ` (${h.binding.member.replace(/^group:/, "")}, if it's a member)` : ""}; change it there`,
                action: (
                  <button type="button" className="link-btn" onClick={() => openMap(focusForGrant({ member: h.binding.member, resource: h.resource }, inv))}>
                    Show on map
                  </button>
                ),
              },
            ]),
          ),
          hintNote:
            change && dest.kind === "mcp_server" && usesHint(ex) ? (
              <>
                <b>Note:</b> today's read-only grant also covers read-only tools added later. Switching to <i>Specific tools</i> pins today's read-only tools and drops “future read-only tools”.
              </>
            ) : undefined,
          change: change && dest.kind !== "mcp_server" ? { who: source.label, current: <>{ex.own.map((b) => (b.condition ? `“${b.condition.title || "conditional"}”: ${b.condition.expression}` : "full access (no condition)")).join("; ")}</> } : undefined,
        }
      : undefined;

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
                                onClick={() => setDestName(d.name)}
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

              <Section
                n={3}
                title="How much of it?"
                sub={change ? "Change the access it has today: the new access replaces every grant below in one change." : dest?.kind === "mcp_server" ? "MCP servers can be limited to some of their tools." : "A2A agents and APIs are all-or-nothing."}
                done={!!intent}
              >
                {!dest ? (
                  <p className="muted">Pick a destination first.</p>
                ) : (
                  <>
                    {change && source && (
                      <Callout tone="info" title="Change existing access">
                        <p className="existing-lead">
                          <b>{source.label}</b> already has access to <b>{dest.label}</b>. Your change replaces it.
                        </p>
                        <ul className="existing-list">
                          {ex.own.map((b, k) => (
                            <li key={k} className="small">
                              {b.english || b.member_label} {b.condition ? <Badge tone="blue">{b.condition.title || "conditional"}</Badge> : <Badge tone="neutral">unconditional</Badge>}
                            </li>
                          ))}
                        </ul>
                        {ex.own.length > 1 && <p className="muted small">{ex.own.length} separate grants: they become one (or are all removed) in a single IAM update.</p>}
                      </Callout>
                    )}
                    <AccessChooser
                      name="how"
                      dest={dest}
                      mcp={mcp}
                      value={{ mode: access, tools, expr, remove }}
                      onChange={(d) => {
                        setAccess(d.mode);
                        setTools(d.tools);
                        setExpr(d.expr);
                        setRemove(!!d.remove);
                      }}
                      extras={chooserExtras}
                    />
                  </>
                )}
              </Section>

              <section className="card preview" aria-live="polite">
                <div className="preview-label">Preview</div>
                {intent ? (
                  <>
                    <p className="preview-sentence">{render?.english ?? intentEnglish(intent)}</p>
                    {change && (intent.kind === "revoke" || removesAll(intent)) && (
                      <Callout tone="danger" title={dest?.kind === "mcp_server" ? "No tool left: this removes the access" : "This removes the access"}>
                        Staged as {intent.kind === "revoke" ? "a revoke of the grant" : `one change that removes all ${ex.own.length} grants`}.
                        {locked.size > 0 && ` Tools allowed by inherited grants (${[...locked.keys()].join(", ")}) stay allowed.`}
                      </Callout>
                    )}
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
                    {!source
                      ? "Choose who is calling (1)…"
                      : !dest
                        ? `${source.label} can call… (choose a destination)`
                        : same
                          ? `No change yet: that's the access ${source.label} has today. Pick different access, or uncheck every tool to remove it.`
                          : access === "custom"
                            ? "Write the condition…"
                            : "Choose at least one tool…"}
                  </p>
                )}
                <div className="preview-actions">
                  <Tip
                    tip={
                      !intent
                        ? same
                          ? "Nothing to change yet."
                          : "Answer the questions above first."
                        : blocking(lint)
                          ? "Fix the condition expression first."
                          : `Preview the change${extraFixes.length ? ` and ${extraFixes.length} fix` : ""} first (a small map and what changes), then approve it to ${editing ? "replace the staged item" : "stage it in the cart"} and open Review & output. Nothing changes in Google Cloud until you apply.`
                    }
                  >
                    <button className="btn btn-primary" disabled={!intent || blocking(lint)} onClick={() => intent && setPreview(openPreview(intent, extraFixes, false, editing ? editId : undefined))}>
                      {editing ? "Save changes" : "Add to cart"}
                      {extraFixes.length > 0 && ` (+${extraFixes.length} fix)`}
                    </button>
                  </Tip>
                  <Tip tip={intent ? "Preview the change, then stage it and start a new one, keeping who is calling. Nothing changes in Google Cloud until you apply." : "Answer the questions above first."}>
                    <button className="btn btn-tonal" disabled={!intent || blocking(lint)} onClick={() => intent && setPreview(openPreview(intent, extraFixes, true, editing ? editId : undefined))}>
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
      {preview && (
        <Suspense
          fallback={
            <div className="glass-backdrop">
              <Spinner label="Loading the preview…" />
            </div>
          }
        >
          <PreviewDialog
            intent={preview.intent}
            extras={preview.extras.length}
            approveLabel={preview.editId ? "Approve: save changes" : preview.another ? "Approve & build another" : "Approve: add to cart"}
            onApprove={onApprove}
            onModify={() => setPreview(null)}
            onCancel={onCancel}
          />
        </Suspense>
      )}
    </>
  );
}
