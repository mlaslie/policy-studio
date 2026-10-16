// "Register a new destination…" (Build step's destination picker and Inventory's "Register…"): an Agent Registry
// entry for an API endpoint or an MCP server, with one or more URLs (a protocol per URL). The checks are the ones
// preflight blocks on (lib/registry.ts checkForm). When an egress gateway in the region has private egress, each URL
// says whether its host is under one of the gateway's private domains (display only).
import { useId, useMemo, useState } from "react";
import type { Gateway, Intent, Inventory } from "../api/types";
import { BINDINGS, BINDING_LABEL, DEFAULT_BINDING, REG_KIND_LABEL, checkForm, emptyForm, privateDomainMatch, privateGateways, suggestServiceId, type RegForm, type RegKind } from "../lib/registry";
import { Choice } from "./AccessChooser";
import { Badge, Callout, Disclosure, Term } from "./ui";
import { PlusIcon, TrashIcon, WarnIcon } from "./Icons";
import { Tip } from "./Tooltip";

export interface RegisterFormProps {
  inv: Inventory | null | undefined;
  gateways: Gateway[];
  region: string;
  cart: Intent[];
  initial?: RegForm;
  submitLabel: string;
  submitTip: string;
  onSubmit: (f: RegForm) => void;
  onCancel: () => void;
}

/** The private-domain hint for one URL: under which gateway domain its host falls (or that it's under none). */
export function PrivateHint({ url, gws }: { url: string; gws: { id: string; vpc: string; domains: string[] }[] }) {
  if (!url.trim() || !gws.length) return null;
  const hits = gws.map((g) => ({ g, d: privateDomainMatch(url, g.domains) })).filter((x) => x.d);
  if (!hits.length)
    return (
      <div className="muted tiny reg-hint" data-testid="private-hint">
        Not under a private domain of {gws.map((g) => g.id).join(", ")} ({[...new Set(gws.flatMap((g) => g.domains))].join(", ")}): the gateway resolves it in public DNS.
      </div>
    );
  return (
    <div className="tiny reg-hint reg-hint-private" data-testid="private-hint">
      {hits.map(({ g, d }) => (
        <span key={g.id}>
          This URL is under <span className="mono">{d}</span>, which the gateway {g.id} resolves inside {g.vpc}.{" "}
        </span>
      ))}
    </div>
  );
}

export function RegisterForm({ inv, gateways, region, cart, initial, submitLabel, submitTip, onSubmit, onCancel }: RegisterFormProps) {
  const [f, setF] = useState<RegForm>(() => initial ?? emptyForm("mcp_server"));
  const [idEdited, setIdEdited] = useState(!!initial?.service_id);
  const [touched, setTouched] = useState(false);
  const uid = useId();
  const check = useMemo(() => checkForm(f, { inv, region, cart }), [f, inv, region, cart]);
  const priv = useMemo(() => privateGateways(gateways), [gateways]);
  const set = (p: Partial<RegForm>) => setF((x) => ({ ...x, ...p }));
  const setKind = (kind: RegKind) =>
    // a protocol still on the other kind's default follows the kind
    setF((x) => ({ ...x, kind, rows: x.rows.map((r) => (r.protocol_binding === DEFAULT_BINDING[x.kind] ? { ...r, protocol_binding: DEFAULT_BINDING[kind] } : r)) }));
  const show = (k: keyof typeof check.errors) => (touched || (k === "service_id" && !!f.service_id) || k === "region" ? check.errors[k] : undefined);

  return (
    <div className="reg-form" role="group" aria-labelledby={`${uid}-title`}>
      <h3 id={`${uid}-title`} className="reg-title">
        Register a new destination
      </h3>
      <p className="muted small">
        An <Term k="agent-registry">Agent Registry</Term> entry with every URL the agents call. Registering isn't access: grant it to an agent too (here, in the same change).
      </p>
      {check.errors.region && <Callout tone="danger" title="Wrong region">{check.errors.region}</Callout>}
      <div className="choices reg-kinds" role="radiogroup" aria-label="What to register">
        <Choice name={`${uid}-kind`} checked={f.kind === "mcp_server"} onChange={() => setKind("mcp_server")} title="MCP server" desc="Tools over MCP (JSON-RPC). Tool conditions need the tool list." />
        <Choice name={`${uid}-kind`} checked={f.kind === "endpoint"} onChange={() => setKind("endpoint")} title="API endpoint" desc="An HTTP API (HTTP + JSON); access is all or nothing." />
      </div>
      <div className="form-grid">
        <div className={`field ${show("display_name") ? "has-error" : ""}`}>
          <label htmlFor={`${uid}-name`}>Display name</label>
          <input
            id={`${uid}-name`}
            value={f.display_name}
            onChange={(e) => {
              const v = e.target.value;
              set(idEdited ? { display_name: v } : { display_name: v, service_id: suggestServiceId(v) });
            }}
            placeholder={f.kind === "mcp_server" ? "Notes MCP" : "Orders API"}
            maxLength={80}
            aria-invalid={!!show("display_name")}
          />
          <div className={`field-help ${show("display_name") ? "field-error" : ""}`}>{show("display_name") ?? "Shown in the registry and on the map."}</div>
        </div>
        <div className={`field ${show("service_id") ? "has-error" : ""}`}>
          <label htmlFor={`${uid}-id`}>Service id</label>
          <input
            id={`${uid}-id`}
            className="mono"
            value={f.service_id}
            onChange={(e) => {
              setIdEdited(true);
              set({ service_id: e.target.value });
            }}
            placeholder="notes-mcp"
            spellCheck={false}
            aria-invalid={!!show("service_id")}
          />
          <div className={`field-help ${show("service_id") ? "field-error" : ""}`}>{show("service_id") ?? "4–63 lowercase letters, digits and hyphens. Can't be changed later."}</div>
        </div>
      </div>
      <div className="field">
        <label id={`${uid}-urls`}>URLs</label>
        <div className="reg-rows" role="list" aria-labelledby={`${uid}-urls`}>
          {f.rows.map((r, k) => {
            const err = check.rowErrors[k];
            return (
              <div key={k} role="listitem" className={`reg-row ${err ? "has-error" : ""}`}>
                <div className="reg-row-line">
                  <input
                    aria-label={`URL ${k + 1}`}
                    className="mono grow"
                    value={r.url}
                    onChange={(e) => set({ rows: f.rows.map((x, j) => (j === k ? { ...x, url: e.target.value } : x)) })}
                    placeholder={f.kind === "mcp_server" ? "https://notes-mcp-123456789012.us-east4.run.app/mcp" : "https://orders.example.com/v1"}
                    spellCheck={false}
                    aria-invalid={!!err}
                  />
                  <select aria-label={`Protocol for URL ${k + 1}`} value={r.protocol_binding} onChange={(e) => set({ rows: f.rows.map((x, j) => (j === k ? { ...x, protocol_binding: e.target.value as RegForm["rows"][number]["protocol_binding"] } : x)) })}>
                    {BINDINGS.map((b) => (
                      <option key={b} value={b}>
                        {BINDING_LABEL[b]}
                      </option>
                    ))}
                  </select>
                  <Tip tip={f.rows.length > 1 ? "Remove this URL." : "An entry needs at least one URL."}>
                    <button type="button" className="mini-btn" aria-label={`Remove URL ${k + 1}`} disabled={f.rows.length === 1} onClick={() => set({ rows: f.rows.filter((_, j) => j !== k) })}>
                      <TrashIcon size={14} />
                    </button>
                  </Tip>
                </div>
                {err && <div className="field-help field-error">{err}</div>}
                <PrivateHint url={r.url} gws={priv} />
              </div>
            );
          })}
        </div>
        <button type="button" className="btn btn-small btn-text" onClick={() => set({ rows: [...f.rows, { url: "", protocol_binding: DEFAULT_BINDING[f.kind] }] })}>
          <PlusIcon size={14} /> Add a URL
        </button>
        {touched && check.errors.rows && <div className="field-help field-error">{check.errors.rows}</div>}
        <div className="field-help">The gateway matches hostnames exactly: register every form agents call (a Cloud Run service has two run.app URLs).</div>
      </div>
      <div className="field">
        <label htmlFor={`${uid}-desc`}>Description (optional)</label>
        <input id={`${uid}-desc`} value={f.description} onChange={(e) => set({ description: e.target.value })} maxLength={2048} />
      </div>
      {f.kind === "mcp_server" && (
        <Disclosure summary="Tool list (optional): paste the server's tools/list response" defaultOpen={!!f.tools_json}>
          <textarea aria-label="tools/list response (JSON)" className="mono reg-tools" rows={5} value={f.tools_json} onChange={(e) => set({ tools_json: e.target.value })} placeholder='{"tools": [{"name": "read_note", "annotations": {"readOnlyHint": true}}]}' spellCheck={false} />
          {check.errors.tools_json && <div className="field-help field-error">{check.errors.tools_json}</div>}
          <div className="field-help">Registered as the entry's tool spec, so read-only and specific-tools grants can match (at most 10 KB).</div>
        </Disclosure>
      )}
      {priv.length === 0 && (
        <p className="muted tiny">No egress gateway in {region || "this region"} has private egress, so these URLs are reached over public DNS.</p>
      )}
      {check.warnings.length > 0 && (
        <div className="checks">
          {check.warnings.map((w) => (
            <div key={w} className="check-chip chip-amber">
              <WarnIcon size={14} />
              <span className="grow">{w}</span>
            </div>
          ))}
        </div>
      )}
      <div className="form-actions">
        <Tip tip={check.ok ? submitTip : "Fix the fields marked above first."}>
          <button
            type="button"
            className="btn btn-primary"
            aria-disabled={!check.ok}
            onClick={() => {
              setTouched(true);
              if (check.ok) onSubmit(f);
            }}
          >
            {submitLabel}
          </button>
        </Tip>
        <button type="button" className="btn btn-text" onClick={onCancel}>
          Cancel
        </button>
        <Badge tone="neutral">{REG_KIND_LABEL[f.kind]}</Badge>
      </div>
    </div>
  );
}
