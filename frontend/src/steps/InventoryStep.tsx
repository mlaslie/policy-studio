// Inventory step: Agent Registry inventory (agents, MCP servers, endpoints) and Agent Runtime engines,
// each with "Who can reach it" and a shortcut into the builder.
import { Tip } from "../components/Tooltip";
import { useMemo, useState } from "react";
import { stepN, useLookup, useStudio } from "../store";
import type { Binding, DestinationPath, Engine, Intent, McpServer, McpTool, RegAgent, ResourceKind } from "../api/types";
import { Badge, Callout, Disclosure, KindIcon, Load, StepHeader, Tabs, Term } from "../components/ui";
import { CopyButton } from "../components/Glass";
import { ArrowIcon, PlusIcon, SearchIcon, TrashIcon, WarnIcon } from "../components/Icons";
import { shortName } from "../lib/policy";
import { fmtDate, plural } from "../lib/util";
import { ShowOnMap } from "../components/ShowOnMap";
import { pscChips } from "../lib/networking";
import { RegisterForm } from "../components/RegisterForm";
import { PathBadge } from "../components/PathBadge";
import { pathOf } from "../lib/paths";
import { GRANTS_LOST, createIntent, deleteIntent } from "../lib/registry";

type Tab = "agents" | "mcp" | "apis" | "engines";

/** A tool's READ / WRITE pill (styles.css .tool-pill: blue for read, amber for write, destructive ones included). */
export function ToolBadge({ t }: { t: McpTool }) {
  const raw = JSON.stringify(t.annotations, null, 1);
  if (t.destructive)
    return (
      <span className="badge tool-pill rw" title={`destructiveHint=true\n${raw}`}>
        WRITE · destructive
      </span>
    );
  return t.read_only ? (
    <span className="badge tool-pill ro" title={`readOnlyHint=true\n${raw}`}>
      READ
    </span>
  ) : (
    <span className="badge tool-pill rw" title={`readOnlyHint is not true\n${raw}`}>
      WRITE
    </span>
  );
}

export function AccessList({ bindings, compact }: { bindings: Binding[] | undefined; compact?: boolean }) {
  if (!bindings) return <p className="muted small">Access couldn't be read.</p>;
  if (!bindings.length) return <p className="muted small">Nobody yet. Agents behind an egress gateway can't reach it.</p>;
  return (
    <ul className={`access-list ${compact ? "compact" : ""}`}>
      {bindings.map((b, i) => {
        const risky = b.member.startsWith("all");
        return (
          <li key={i} className={risky ? "risky" : ""}>
            <span className="access-english">
              {risky && <WarnIcon size={13} />} {b.english}
            </span>
            <span className="access-meta">
              {b.condition ? (
                <span className="badge badge-blue" title={`${b.condition.title}\n${b.condition.expression}`}>
                  conditional
                </span>
              ) : (
                <span className="badge badge-neutral" title="No condition: the whole destination">
                  unconditional
                </span>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function matches(q: string, ...fields: (string | undefined)[]) {
  if (!q) return true;
  const s = q.toLowerCase();
  return fields.some((f) => f?.toLowerCase().includes(s));
}

function destOf(kind: ResourceKind, x: { id: string; name: string; display_name: string }): Intent["destination"] {
  return { kind, id: x.id, name: x.name, label: x.display_name };
}

function BuildBtn({ dest }: { dest: Intent["destination"] }) {
  const { openBuilder } = useStudio();
  return (
    <>
      <ShowOnMap focus={dest ? { direction: "egress", node: dest.name } : null} what={dest?.label ?? "this destination"} compact />
      <Tip tip={`Open the builder with ${dest?.label ?? "this destination"} filled in as what may be called. Nothing is staged yet.`}>
        <button className="btn btn-small btn-tonal" onClick={() => openBuilder({ kind: "grant", destination: dest })}>
          Build a policy for this <ArrowIcon size={14} />
        </button>
      </Tip>
    </>
  );
}

/** "Delete entry…": stages the delete of the registry Service behind an entry (after a confirm that says what goes with
 *  it). Entries the platform registered (no Service) can't be deleted here. */
export function DeleteEntry({ entry, access }: { entry: { name: string; display_name: string; service?: string | null }; access?: Binding[] }) {
  const { inventory, addIntents, cart } = useStudio();
  const [asking, setAsking] = useState(false);
  const svc = inventory.data?.services?.find((x) => x.name === entry.service);
  if (!svc || svc.kind === "agent") return null;
  const staged = cart.some((i) => i.kind === "registry_service" && i.params?.delete && i.params.service_id === svc.id);
  const n = access?.length ?? 0;
  if (staged) return <Badge tone="amber">deletion staged</Badge>;
  if (!asking)
    return (
      <Tip tip={`Stage deleting ${entry.display_name} from the Agent Registry (asks first). Nothing changes in Google Cloud until you apply.`}>
        <button className="btn btn-small btn-text" onClick={() => setAsking(true)}>
          <TrashIcon size={14} /> Delete entry…
        </button>
      </Tip>
    );
  return (
    <div className="reg-delete-confirm" role="alertdialog" aria-label={`Delete ${entry.display_name}?`}>
      <span className="small">
        Delete <b>{entry.display_name}</b> (<span className="mono">{svc.id}</span>)? {n ? `${n} grant${n === 1 ? "" : "s"} on it ${n === 1 ? "is" : "are"} removed with it. ` : ""}
        {GRANTS_LOST}.
      </span>
      <button
        className="btn btn-small btn-danger"
        onClick={() => {
          addIntents([deleteIntent(svc)]);
          setAsking(false);
        }}
      >
        Stage delete
      </button>
      <button className="btn btn-small btn-text" onClick={() => setAsking(false)}>
        Cancel
      </button>
    </div>
  );
}

/** Where a destination's calls went, seen in the gateway request logs (Sync reads them in the background). */
type Traffic = { path: DestinationPath | null | undefined; window: string };

function AgentCard({ a, access, engine, traffic }: { a: RegAgent; access?: Binding[]; engine?: Engine; traffic: Traffic }) {
  return (
    <article className="card asset">
      <header className="asset-head">
        <KindIcon kind="agent" size={18} />
        <div className="grow">
          <h3>{a.display_name}</h3>
          <div className="muted tiny">
            {a.kind === "a2a" ? <Badge tone="purple">A2A agent</Badge> : <Badge tone="blue">Agent Runtime</Badge>} <span className="mono">{a.id}</span>
            {a.url && <span className="mono"> · {a.url.replace(/^https:\/\//, "")}</span>} <PathBadge path={traffic.path} window={traffic.window} />
          </div>
        </div>
        <BuildBtn dest={destOf("agent", a)} />
      </header>
      {a.skills.length > 0 && (
        <div className="skills">
          {a.skills.map((s) => (
            <span key={s.id} className="skill" title={s.description}>
              {s.name}
            </span>
          ))}
        </div>
      )}
      {engine && !engine.gateways.ingress && a.kind === "runtime" && <p className="muted small">Not behind an ingress gateway.</p>}
      <div className="who">
        <h4>Who can reach it</h4>
        <AccessList bindings={access} />
      </div>
    </article>
  );
}

function McpCard({ m, access, traffic }: { m: McpServer; access?: Binding[]; traffic: Traffic }) {
  const ro = m.tools.filter((t) => t.read_only).length;
  return (
    <article className="card asset">
      <header className="asset-head">
        <KindIcon kind="mcp_server" size={18} />
        <div className="grow">
          <h3>{m.display_name}</h3>
          <div className="muted tiny">
            <Badge tone="green">MCP server</Badge> <span className="mono">{m.id}</span> · {plural(m.tools.length, "tool")}, {ro} read-only <PathBadge path={traffic.path} window={traffic.window} />
          </div>
        </div>
        <BuildBtn dest={destOf("mcp_server", m)} />
      </header>
      <DeleteEntry entry={m} access={access} />
      <table className="tools-table">
        <thead>
          <tr>
            <th>Tool</th>
            <th>What it does</th>
            <th>
              <Term k="mcp-hints">Hint</Term>
            </th>
          </tr>
        </thead>
        <tbody>
          {m.tools.map((t) => (
            <tr key={t.name}>
              <td className="mono small">{t.name}</td>
              <td className="small">{t.description}</td>
              <td>
                <ToolBadge t={t} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="who">
        <h4>Who can reach it</h4>
        <AccessList bindings={access} />
      </div>
    </article>
  );
}

function EngineCard({ e }: { e: Engine }) {
  const { openBuilder } = useStudio();
  const { egress } = useLookup();
  return (
    <article className="card asset">
      <header className="asset-head">
        <KindIcon kind="engine" size={18} />
        <div className="grow">
          <h3>{e.display_name}</h3>
          <div className="muted tiny">
            <span className="mono">reasoningEngines/{e.id}</span> · created {fmtDate(e.create_time)}
          </div>
        </div>
        <ShowOnMap focus={{ direction: "egress", node: e.name }} what={e.display_name} compact />
        <Tip tip={`Open the builder with ${e.display_name} filled in as the caller. Nothing is staged yet.`}>
          <button
            className="btn btn-small btn-tonal"
            onClick={() => openBuilder({ kind: "grant", source: { type: "engine", principal: e.principal, label: e.display_name, engine: e.name } })}
          >
            Build a policy from this agent <ArrowIcon size={14} />
          </button>
        </Tip>
      </header>
      <div className="engine-gw">
        <span>
          Egress:{" "}
          {e.gateways.egress ? <Badge tone="green">{shortName(e.gateways.egress)}</Badge> : <Badge tone="red">not bound: calls go out unchecked</Badge>}
        </span>
        <span>
          Ingress: {e.gateways.ingress ? <Badge tone="green">{shortName(e.gateways.ingress)}</Badge> : <Badge tone="neutral">not bound</Badge>}
        </span>
        <span>{e.bindable ? <Badge tone="neutral">bindable</Badge> : <Badge tone="amber" title={e.bindable_reason ?? "Created before 2026-04-29"}>can't be bound</Badge>}</span>
        <span data-testid="private-networking">
          <Term k="psc-interface">Private networking</Term>:{" "}
          {e.psc_interface ? (
            pscChips(e).map((c, i) => (
              <span key={c.text}>
                {i > 0 && " "}
                <Badge tone="red" title={c.tip}>
                  {c.text}
                  {i === 0 && e.psc_interface?.vpc ? ` · ${e.psc_interface.vpc}` : ""}
                </Badge>
              </span>
            ))
          ) : (
            <Badge tone="neutral">none</Badge>
          )}
        </span>
      </div>
      {!e.gateways.egress && egress && e.bindable && <p className="small muted">Bind it to {egress.id} in step {stepN("gateways")} (Gateways) so its grants are enforced.</p>}
      <div className="principal">
        <div className="principal-head">
          <span>
            <Term k="agent-identity">Agent Identity</Term> <span className="muted small">({e.identity_type})</span>
          </span>
          <CopyButton compact className="mini-btn" ariaLabel={`Copy ${e.display_name}'s principal`} tip="Copy this agent's principal (its Agent Identity) to the clipboard." getText={() => e.principal} />
        </div>
        <code className="principal-value">{e.principal}</code>
        <Disclosure summary="What is this?">
          <p className="small">
            This is <b>{e.display_name}</b>'s own identity. When it calls something through the egress gateway, IAP checks whether <i>this</i> principal holds{" "}
            <span className="mono">roles/iap.egressor</span> on the destination. You don't need to copy it: when you pick this agent in the builder, Policy Studio uses it for you.
          </p>
        </Disclosure>
      </div>
    </article>
  );
}

export function InventoryStep() {
  const { inventory, gateways, ctx, cart, addIntents, paths } = useStudio();
  const [registering, setRegistering] = useState(false);
  const [tab, setTab] = useState<Tab>("agents");
  const [q, setQ] = useState("");
  const [showAllEndpoints, setShowAll] = useState(false);
  const { engineByName } = useLookup();

  return (
    <>
      <StepHeader
        title="Inventory"
        lead={
          <>
            Everything your agents can be allowed to call, from the <Term k="agent-registry">Agent Registry</Term>, and the <Term k="runtime">Agent Runtime agents</Term> that do the calling. Each
            entry shows who can reach it today.
          </>
        }
      />
      <Load l={inventory} what="the inventory">
        {(inv) => {
          const agents = inv.agents.filter((a) => matches(q, a.display_name, a.id, a.url, ...a.skills.map((s) => s.name)));
          const mcps = inv.mcp_servers.filter((m) => matches(q, m.display_name, m.id, ...m.tools.map((t) => t.name)));
          const eps = inv.endpoints.filter((e) => matches(q, e.display_name, e.id, e.url));
          const engs = inv.engines.filter((e) => matches(q, e.display_name, e.id, e.principal));
          const visibleEps = showAllEndpoints || q ? eps : eps.slice(0, 6);
          const traffic = (name: string): Traffic => ({ path: pathOf(paths.data, name), window: paths.data?.window ?? "7d" });
          return (
            <>
              <div className="toolbar">
                <Tabs<Tab>
                  label="Inventory type"
                  value={tab}
                  onChange={setTab}
                  items={[
                    { id: "agents", label: "Agents", count: agents.length },
                    { id: "mcp", label: "MCP servers", count: mcps.length },
                    { id: "apis", label: "APIs", count: eps.length },
                    { id: "engines", label: "Agent Runtime engines", count: engs.length },
                  ]}
                />
                <label className="search">
                  <SearchIcon size={16} />
                  <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search names, tools, skills…" aria-label="Search inventory" />
                </label>
                <Tip tip="Register an API endpoint or an MCP server in the Agent Registry (staged in the cart). To grant it in the same change, use Build a policy → Register a new destination.">
                  <button className="btn btn-small btn-tonal" onClick={() => setRegistering(true)} disabled={registering}>
                    <PlusIcon size={14} /> Register…
                  </button>
                </Tip>
              </div>
              {registering && (
                <RegisterForm
                  inv={inv}
                  gateways={gateways.data?.gateways ?? []}
                  region={ctx.region}
                  cart={cart}
                  submitLabel="Stage registration"
                  submitTip="Stage the new registry entry in the cart. Nothing changes in Google Cloud until you apply."
                  onSubmit={(f) => {
                    addIntents([createIntent(f)]);
                    setRegistering(false);
                  }}
                  onCancel={() => setRegistering(false)}
                />
              )}
              {tab === "agents" && (
                <div className="asset-list">
                  {agents.map((a) => (
                    <AgentCard key={a.name} a={a} access={inv.access[a.name]} engine={a.engine ? engineByName.get(a.engine) : undefined} traffic={traffic(a.name)} />
                  ))}
                  {!agents.length && <p className="muted">No agents match.</p>}
                </div>
              )}
              {tab === "mcp" && (
                <div className="asset-list">
                  {mcps.map((m) => (
                    <McpCard key={m.name} m={m} access={inv.access[m.name]} traffic={traffic(m.name)} />
                  ))}
                  {!mcps.length && <p className="muted">No MCP servers match.</p>}
                </div>
              )}
              {tab === "apis" && (
                <div className="card">
                  <p className="muted small">API endpoints are hosts (usually Google APIs) registered so agents can call them through the gateway.</p>
                  <table className="ep-table">
                    <thead>
                      <tr>
                        <th>Endpoint</th>
                        <th>Host</th>
                        <th>Who can reach it</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {visibleEps.map((e) => (
                        <tr key={e.name}>
                          <td>
                            <b>{e.display_name}</b>
                            {/* where its calls went (seen in traffic), under the name: the table has no room for a column */}
                            <div className="ep-path">
                              <PathBadge {...traffic(e.name)} />
                            </div>
                          </td>
                          <td className="mono small">{e.url.replace(/^https:\/\//, "")}</td>
                          <td>
                            <AccessList compact bindings={inv.access[e.name] ?? []} />
                          </td>
                          <td>
                            <div className="reg-entry-actions">
                              <BuildBtn dest={destOf("endpoint", e)} />
                              <DeleteEntry entry={e} access={inv.access[e.name]} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!q && eps.length > 6 && (
                    <button className="link-btn" onClick={() => setShowAll(!showAllEndpoints)}>
                      {showAllEndpoints ? "Show fewer" : `Show all ${eps.length} endpoints`}
                    </button>
                  )}
                </div>
              )}
              {tab === "engines" && (
                <>
                  <Callout tone="info" title="These are the callers">
                    Agent Runtime engines are the agents that <i>make</i> calls. Each has an <Term k="agent-identity">Agent Identity</Term>; grants name that identity.
                  </Callout>
                  <div className="asset-list">
                    {engs.map((e) => (
                      <EngineCard key={e.name} e={e} />
                    ))}
                  </div>
                </>
              )}
            </>
          );
        }}
      </Load>
    </>
  );
}

export function useDestinations() {
  const { inventory } = useStudio();
  return useMemo(() => {
    const inv = inventory.data;
    if (!inv) return [];
    return [
      ...inv.agents.map((a) => ({ ...destOf("agent", a)!, sub: a.kind === "a2a" ? "A2A agent" : "Agent Runtime agent" })),
      ...inv.mcp_servers.map((m) => ({ ...destOf("mcp_server", m)!, sub: `MCP server · ${m.tools.length} tools` })),
      ...inv.endpoints.map((e) => ({ ...destOf("endpoint", e)!, sub: e.url.replace(/^https:\/\//, "") })),
    ];
  }, [inventory.data]);
}
