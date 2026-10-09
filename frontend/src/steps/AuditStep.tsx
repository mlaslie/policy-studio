// Step 7: audit: summary tiles, grants in plain English with filters, findings with fixes, Terraform export.
import { useEffect, useState } from "react";
import { useLookup, useStudio } from "../store";
import { api } from "../api/client";
import type { Finding, Grant, RenderResult } from "../api/types";
import { Badge, Callout, KindIcon, Load, StepHeader, Term } from "../components/ui";
import { GlassModal } from "../components/Glass";
import { CodeView } from "../components/CodeView";
import { AuditIcon, DownloadIcon, PencilIcon, TrashIcon, WarnIcon, CheckIcon, InfoIcon } from "../components/Icons";
import { grantToIntent } from "../lib/grants";
import { downloadBlob, makeZip } from "../lib/zip";
import { ago } from "../lib/util";
import { KIND_LABEL } from "../lib/policy";

const SEV: Record<Finding["severity"], { tone: "red" | "amber" | "neutral"; label: string }> = {
  high: { tone: "red", label: "High" },
  medium: { tone: "amber", label: "Medium" },
  info: { tone: "neutral", label: "Info" },
};

function Tile({ label, value, sub, tone }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: "red" | "amber" | "green" }) {
  return (
    <div className={`tile ${tone ? `tile-${tone}` : ""}`}>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  );
}

function ExportModal({ onClose }: { onClose: () => void }) {
  const { audit, ctx } = useStudio();
  const { engineByPrincipal } = useLookup();
  const [res, setRes] = useState<RenderResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const grants = (audit.data?.grants ?? []).filter((g) => !g.member.startsWith("all"));
  useEffect(() => {
    api
      .render(ctx, grants.map((g) => grantToIntent(g, engineByPrincipal, "grant")))
      .then(setRes)
      .catch((e) => setErr(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const skipped = (audit.data?.grants.length ?? 0) - grants.length;
  return (
    <GlassModal
      title="Export current grants as Terraform"
      subtitle={`${grants.length} grants in ${ctx.project} / ${ctx.region}`}
      icon={<DownloadIcon size={18} />}
      onClose={onClose}
      actions={
        res && (
          <button
            className="glass-btn"
            onClick={() =>
              downloadBlob(
                makeZip([
                  { name: "current-grants/main.tf", content: res.bundle.terraform["main.tf"] },
                  { name: "current-grants/variables.tf", content: res.bundle.terraform["variables.tf"] },
                ]),
                `current-grants-${ctx.project}.zip`,
              )
            }
          >
            <DownloadIcon size={15} /> Download
          </button>
        )
      }
    >
      <p className="sheet-explain">
        Use this to bring existing grants under Terraform. Import each resource before the first <span className="mono">terraform apply</span> so Terraform doesn't try to create duplicates.
        {skipped > 0 && ` ${skipped} public grant${skipped > 1 ? "s were" : " was"} left out on purpose.`}
      </p>
      {err && <Callout tone="danger" title="Export failed">{err}</Callout>}
      {res ? (
        <>
          <CodeView code={res.bundle.terraform["main.tf"]} lang="hcl" label="main.tf" />
          <div style={{ height: 12 }} />
          <CodeView code={res.bundle.terraform["variables.tf"]} lang="hcl" label="variables.tf" />
        </>
      ) : (
        !err && <p className="muted">Rendering…</p>
      )}
    </GlassModal>
  );
}

export function AuditStep() {
  const { audit, gateways, inventory, addIntents, openBuilder, cart, syncedAt } = useStudio();
  const { engineByPrincipal } = useLookup();
  const [who, setWho] = useState("");
  const [dest, setDest] = useState("");
  const [cond, setCond] = useState<"" | "conditional" | "unconditional">("");
  const [exporting, setExporting] = useState(false);

  const staged = (f: Finding) => !!f.fix && cart.some((c) => c.kind === f.fix!.kind && JSON.stringify({ ...c, id: "" }) === JSON.stringify({ ...f.fix!, id: "" }));
  const revokeStaged = (g: Grant) => cart.some((c) => c.kind === "revoke" && c.source?.principal === g.member && c.destination?.name === g.resource);

  return (
    <>
      <StepHeader
        title="Audit"
        lead={<>Everything currently allowed in this project and region, in plain English, with problems flagged. Fixes are staged in the cart so you can review them first.</>}
        actions={
          <button className="btn btn-tonal" onClick={() => setExporting(true)} disabled={!audit.data}>
            <DownloadIcon size={16} /> Export as Terraform
          </button>
        }
      />
      <Load l={audit} what="the audit">
        {(a) => {
          const gws = gateways.data?.gateways ?? [];
          const engines = inventory.data?.engines ?? [];
          const behind = engines.filter((e) => e.gateways.egress).length;
          const conditional = a.grants.filter((g) => g.condition).length;
          const bySev = (s: Finding["severity"]) => a.findings.filter((f) => f.severity === s).length;
          const members = [...new Set(a.grants.map((g) => g.member_label))].sort();
          const dests = [...new Set(a.grants.map((g) => g.resource_label))].sort();
          const rows = a.grants.filter((g) => (!who || g.member_label === who) && (!dest || g.resource_label === dest) && (!cond || (cond === "conditional" ? !!g.condition : !g.condition)));
          const maOn = gws.filter((g) => g.authz_policies.some((p) => p.provider === "model_armor")).length;
          return (
            <>
              <div className="tiles">
                <Tile label="Gateways" value={gws.length} sub={`${maOn} with Model Armor`} />
                <Tile label="Agents behind an egress gateway" value={`${behind} / ${engines.length}`} sub={engines.length - behind ? `${engines.length - behind} unprotected` : "all protected"} tone={engines.length - behind ? "amber" : "green"} />
                <Tile label="Grants" value={a.grants.length} sub={`${conditional} conditional`} />
                <Tile
                  label="Findings"
                  value={
                    <span className="sev-row">
                      <Badge tone="red">{bySev("high")} high</Badge>
                      <Badge tone="amber">{bySev("medium")} med</Badge>
                      <Badge tone="neutral">{bySev("info")} info</Badge>
                    </span>
                  }
                  sub={`synced ${ago(syncedAt, Date.now())}`}
                  tone={bySev("high") ? "red" : undefined}
                />
              </div>

              <section className="card">
                <h2 className="card-title">
                  <AuditIcon size={18} /> Findings
                </h2>
                {a.findings.length === 0 ? (
                  <Callout tone="ok" title="No findings">Nothing looks off.</Callout>
                ) : (
                  <ul className="findings">
                    {a.findings.map((f, i) => (
                      <li key={i} className={`finding sev-${f.severity}`}>
                        <span className="finding-icon">{f.severity === "info" ? <InfoIcon size={18} /> : <WarnIcon size={18} />}</span>
                        <div className="grow">
                          <div className="finding-title">
                            <Badge tone={SEV[f.severity].tone}>{SEV[f.severity].label}</Badge> {f.title}
                          </div>
                          <p className="small">{f.detail}</p>
                          {f.fix && (
                            <div className="row">
                              {staged(f) ? (
                                <Badge tone="green">
                                  <CheckIcon size={12} /> Fix staged
                                </Badge>
                              ) : (
                                <button className="btn btn-small btn-primary" onClick={() => addIntents([{ ...f.fix! }])}>
                                  Stage fix: {KIND_LABEL[f.fix.kind].toLowerCase()}
                                </button>
                              )}
                              {(f.fix.kind === "grant" || f.fix.kind === "revoke") && (
                                <button className="btn btn-small btn-text" onClick={() => openBuilder(f.fix!, { mode: f.fix!.kind === "revoke" ? "revoke" : "grant" })}>
                                  <PencilIcon size={14} /> Edit in builder
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              <section className="card">
                <div className="card-title-row">
                  <h2 className="card-title">Who can call what</h2>
                  <div className="filters">
                    <select value={who} onChange={(e) => setWho(e.target.value)} aria-label="Filter by agent">
                      <option value="">All callers</option>
                      {members.map((m) => (
                        <option key={m}>{m}</option>
                      ))}
                    </select>
                    <select value={dest} onChange={(e) => setDest(e.target.value)} aria-label="Filter by destination">
                      <option value="">All destinations</option>
                      {dests.map((m) => (
                        <option key={m}>{m}</option>
                      ))}
                    </select>
                    <select value={cond} onChange={(e) => setCond(e.target.value as typeof cond)} aria-label="Filter by condition">
                      <option value="">Any condition</option>
                      <option value="conditional">Conditional only</option>
                      <option value="unconditional">Unconditional only</option>
                    </select>
                  </div>
                </div>
                <p className="muted small">
                  Each row is one <Term k="iap-egressor">roles/iap.egressor</Term> grant on an <Term k="agent-registry">Agent Registry</Term> entry.
                </p>
                <table className="grants-table">
                  <colgroup>
                    <col style={{ width: "42%" }} />
                    <col style={{ width: "17%" }} />
                    <col style={{ width: "17%" }} />
                    <col style={{ width: "14%" }} />
                    <col style={{ width: "10%" }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>In plain English</th>
                      <th>Caller</th>
                      <th>Destination</th>
                      <th>Scope</th>
                      <th aria-label="Actions" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((g, i) => {
                      const e = engineByPrincipal.get(g.member);
                      const unprotected = e && !e.gateways.egress;
                      return (
                        <tr key={i} className={g.member.startsWith("all") ? "risky" : ""}>
                          <td>
                            {g.english}
                            {unprotected && (
                              <div className="small warn-text">
                                <WarnIcon size={12} /> not enforced: {e.display_name} isn't behind an egress gateway
                              </div>
                            )}
                          </td>
                          <td className="small" title={g.member}>
                            {g.member_label.replace(/ \(Agent Identity\)$/, "")}
                          </td>
                          <td className="small">
                            <span className="inline-icon">
                              <KindIcon kind={g.resource_kind} size={14} /> {g.resource_label}
                            </span>
                          </td>
                          <td>{g.condition ? <Badge tone="blue" title={g.condition.expression}>{g.condition.title}</Badge> : <Badge tone="neutral">Unconditional</Badge>}</td>
                          <td className="actions-cell">
                            <button className="icon-btn" title="Edit in builder" aria-label={`Edit: ${g.english}`} onClick={() => openBuilder(grantToIntent(g, engineByPrincipal, "grant"), { mode: "grant" })}>
                              <PencilIcon size={14} />
                            </button>
                            {revokeStaged(g) ? (
                              <Badge tone="red">revoke staged</Badge>
                            ) : (
                              <button className="icon-btn danger" title="Stage revoke" aria-label={`Revoke: ${g.english}`} onClick={() => addIntents([grantToIntent(g, engineByPrincipal, "revoke")])}>
                                <TrashIcon size={14} />
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {!rows.length && (
                      <tr>
                        <td colSpan={5} className="muted">
                          No grants match these filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </section>
              {exporting && <ExportModal onClose={() => setExporting(false)} />}
            </>
          );
        }}
      </Load>
    </>
  );
}
