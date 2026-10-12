// Prerequisite and redundancy checks for a grant before it's staged (pulled out of the builder so the policy map's
// panel shows the same warnings): no egress gateway, unregistered destination, an exact duplicate, an existing grant
// a new one would sit next to, a broader grant, destructive tools, project-wide reach.
import { useMemo } from "react";
import type { Binding, Engine, Gateway, Grant, Intent, Inventory } from "../api/types";
import { useLookup, useStudio } from "../store";
import { grantToModify } from "./grants";
import { ROLE, conditionFor, newId } from "./policy";

/** A check shown as an amber chip with an optional "also stage fix", or an intent to stage instead of this one
 *  (`instead`, e.g. a modify of the existing grant). */
export type Check = { id: string; tone: "amber" | "info" | "red"; text: string; fix?: Intent; fixLabel?: string; instead?: Intent; insteadLabel?: string; insteadTip?: string };

export interface CheckInput {
  inv: Inventory | null | undefined;
  cart: Intent[];
  engineByName: Map<string, Engine>;
  engineByPrincipal: Map<string, Engine>;
  egress?: Gateway;
}

export function checksFor(intent: Intent | null, { inv, cart, engineByName, engineByPrincipal, egress }: CheckInput): Check[] {
  const out: Check[] = [];
  if (!intent || !inv || intent.kind !== "grant" || !intent.source || !intent.destination) return out;
  const src = intent.source;
  const dest = intent.destination;
  if (src.type === "engine" && src.engine) {
    const e = engineByName.get(src.engine);
    if (e && !e.gateways.egress) {
      const staged = cart.some((i) => i.kind === "bind_gateway" && i.engine === e.name && i.gateway?.direction === "egress");
      if (!e.bindable) out.push({ id: "nobind", tone: "red", text: `${e.display_name} isn't behind an egress gateway and can't be bound (${e.bindable_reason ?? "created before 2026-04-29"}). This grant won't be checked until it is redeployed.` });
      else if (staged) out.push({ id: "bindstaged", tone: "info", text: `${e.display_name} will be bound to an egress gateway (already in your cart).` });
      else
        out.push({
          id: "bind",
          tone: "amber",
          text: `${e.display_name} isn't behind an egress gateway, so its calls go out directly and this grant is never checked.`,
          fix: egress ? { id: newId(), kind: "bind_gateway", gateway: { name: egress.name, direction: "egress" }, engine: e.name, engine_label: e.display_name } : undefined,
          fixLabel: egress ? `Also stage: bind to ${egress.id}` : undefined,
        });
    }
  }
  const all = [...inv.agents.map((a) => a.name), ...inv.mcp_servers.map((m) => m.name), ...inv.endpoints.map((x) => x.name)];
  if (dest.kind !== "registry" && !all.includes(dest.name)) out.push({ id: "unreg", tone: "amber", text: `${dest.label} isn't in the Agent Registry for this region. The gateway can't route to unregistered destinations; register it first.` });

  const current: Binding[] = inv.access[dest.name] ?? [];
  const cond = conditionFor(intent.access);
  const mine = current.filter((b) => b.member === src.principal && b.role === ROLE);
  if (mine.some((b) => (b.condition?.expression ?? "") === (cond?.expression ?? ""))) out.push({ id: "dup", tone: "info", text: "This exact grant already exists. Adding it again changes nothing." });
  else if (mine.length) {
    // IAM adds bindings rather than replacing them: a grant would sit next to the existing one, which keeps its
    // access. A modify swaps the existing binding (its exact condition) for this access in one change.
    const g: Grant = { ...mine[0], resource: dest.name, resource_kind: dest.kind, resource_label: dest.label };
    const more = mine.length > 1 ? ` and ${mine.length - 1} more grant${mine.length > 2 ? "s" : ""}` : "";
    out.push({
      id: "replace",
      tone: "amber",
      text: `${src.label} already has ${mine[0].condition ? "conditional" : "unconditional"} access here (“${mine[0].english}”)${more}. IAM adds this grant as a second binding next to it, so the existing access stays as it is.`,
      instead: { ...grantToModify(g, engineByPrincipal, intent.access ?? { mode: "all" }), source: src, destination: dest },
      insteadLabel: "Change the existing grant instead",
      insteadTip: "Stage one change that replaces the existing grant's access with this one (a single IAM update, so there's no moment with both or neither). Nothing changes in Google Cloud until you apply.",
    });
  }
  const broader = current.find((b) => b.role === ROLE && !b.condition && b.member !== src.principal && (b.member.startsWith("principalSet://") || b.member.startsWith("all")) && src.type !== "project_agents");
  if (broader) out.push({ id: "broader", tone: "amber", text: `An existing broader grant already allows this: “${broader.english}”. Your narrower grant won't restrict it.` });
  if (intent.access?.mode === "all" && dest.kind === "mcp_server") {
    const d = inv.mcp_servers.find((m) => m.name === dest.name)?.tools.filter((t) => t.destructive) ?? [];
    if (d.length) out.push({ id: "destructive", tone: "amber", text: `Full access includes destructive tools (${d.map((t) => t.name).join(", ")}). Consider “Read-only by MCP hint”.` });
  }
  if (src.type === "project_agents") out.push({ id: "broad", tone: "info", text: "Every agent in the project gets this, including agents created later." });
  return out;
}

/** checksFor with the studio's inventory, cart and lookups. */
export function useChecks(intent: Intent | null): Check[] {
  const { inventory, cart } = useStudio();
  const { engineByName, engineByPrincipal, egress } = useLookup();
  return useMemo(() => checksFor(intent, { inv: inventory.data, cart, engineByName, engineByPrincipal, egress }), [intent, inventory.data, engineByName, engineByPrincipal, egress, cart]);
}
