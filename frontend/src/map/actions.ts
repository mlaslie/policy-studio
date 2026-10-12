// What the policy panel stages (docs/VISUALIZATION_PLAN.md §6.3, §9): intents built from a line's reasons, or from a
// Client-to-Agent line's gateway and agents; never written directly. Pure, so the exact intents are tested.
import type { Access, AuthzPolicy, Direction as GwDirection, Engine, Gateway, Grant, Intent, ModelArmorGateway, ModelArmorResp } from "../api/types";
import { grantToIntent, grantToModify, grantToRevoke } from "../lib/grants";
import { conditionFor, newId, shortName } from "../lib/policy";
import type { PEdge, PNode, Reason } from "./graph";
import { CLIENT, NOGW } from "./ids";
import { memberMatches } from "./evaluate";

/** A line's reason as the Grant the audit lists (the same shape grants.ts turns into intents). */
export const reasonGrant = (r: Reason): Grant => ({ ...r.binding, resource: r.resource, resource_kind: r.resourceKind, resource_label: r.resourceLabel });

/** Revoke: the binding with its exact condition. */
export const revokeFor = (r: Reason, byPrincipal: Map<string, Engine>): Intent => grantToRevoke(reasonGrant(r), byPrincipal);

/** Change access: one modify from the binding's exact condition to `access`. */
export const modifyFor = (r: Reason, byPrincipal: Map<string, Engine>, access: Access): Intent => grantToModify(reasonGrant(r), byPrincipal, access);

/** Is `access` the binding's current access (same condition expression)? Then there's nothing to change. */
export function sameAccess(r: Reason, access: Access): boolean {
  const norm = (e: string | undefined) => (e ?? "").replace(/\s+/g, " ").trim();
  return norm(conditionFor(access)?.expression) === norm(r.binding.condition?.expression);
}

/** A group, public or other binding that reaches the agent but doesn't name it. */
export const isGroupGrant = (r: Reason, engine: Engine | undefined) => !!engine && r.binding.member !== engine.principal;

/** The agents of the inventory a group binding reaches (for "removes access for all N agents"). */
export const reachedBy = (member: string, engines: Engine[]) => engines.filter((e) => memberMatches(member, e.principal) !== false);

/** "Limit to this agent instead": the same access granted to this agent alone, plus the revoke of the group binding. */
export function limitToAgent(r: Reason, engine: Engine, byPrincipal: Map<string, Engine>): Intent[] {
  const g = reasonGrant(r);
  const revoke = grantToRevoke(g, byPrincipal);
  const grant = grantToIntent({ ...g, member: engine.principal, member_label: engine.display_name }, byPrincipal, "grant");
  return [{ ...grant, source: { type: "engine", principal: engine.principal, label: engine.display_name, engine: engine.name } }, revoke];
}

/** Allow… on a default-deny line: a grant from this agent to the destination node. */
export function allowFor(engine: Engine, dest: PNode, access: Access): Intent {
  const kind = dest.destKind ?? "endpoint";
  return {
    id: newId(),
    kind: "grant",
    source: { type: "engine", principal: engine.principal, label: engine.display_name, engine: engine.name },
    // registry = a registry-wide grant: id "", name projects/P/locations/R (API.md)
    destination: { kind, id: kind === "registry" ? "" : shortName(dest.id), name: dest.id, label: dest.label },
    access,
  };
}

/** Bind an agent with no gateway (in that direction) to a gateway: egress unless told otherwise. */
export const bindFor = (engine: Pick<Engine, "name" | "display_name">, gw: Pick<Gateway, "name">, direction: GwDirection = "egress"): Intent => ({
  id: newId(),
  kind: "bind_gateway",
  gateway: { name: gw.name, direction },
  engine: engine.name,
  engine_label: engine.display_name,
});

/** Unbind an agent from a gateway (destructive: Apply asks to acknowledge it). */
export const unbindFor = (engine: Pick<Engine, "name" | "display_name">, gw: Pick<Gateway, "name" | "type">): Intent => ({
  id: newId(),
  kind: "unbind_gateway",
  gateway: { name: gw.name, direction: gw.type },
  engine: engine.name,
  engine_label: engine.display_name,
});

/** Turn Model Armor on or off on a gateway (off is destructive: it removes the CONTENT_AUTHZ policy). */
export const modelArmorFor = (gw: Pick<Gateway, "name" | "type">, on: boolean): Intent => ({ id: newId(), kind: on ? "model_armor_on" : "model_armor_off", gateway: { name: gw.name, direction: gw.type } });

// ---------- a Client-to-Agent line (§6.3) ----------
export interface IngressInfo {
  /** The ingress gateway on the line (null: the agents aren't bound for ingress, calls reach them directly). */
  gateway: Gateway | null;
  ma: ModelArmorGateway | null;
  /** Model Armor on this gateway: off → on, on → off, or the guided setup first when the region has no Model Armor
   *  authz extension to turn it on with. Null without a gateway. */
  maAction: { kind: "on" | "off"; intent: Intent } | { kind: "setup" } | null;
  /** An IAP REQUEST_AUTHZ policy on the gateway, exactly as configured (Client-to-Agent doesn't check it). */
  iap: AuthzPolicy | null;
  /** The agents on this line that are bound to the gateway, each with its unbind. */
  bound: { engine: Engine; unbind: Intent }[];
  /** The agents on this line with no ingress gateway: the gateways they can be bound to, or why they can't. */
  unbound: { engine: Engine; why: string | null }[];
  /** The region's ingress gateways (the Bind choices). */
  ingress: Gateway[];
}

/** What the panel shows and stages for a Client-to-Agent line, from today's state. The agents on it: the line's own
 *  agent (gateway or "no ingress gateway" → agent), or every agent behind that lane (client → gateway or → no
 *  gateway). */
export function ingressInfo(edge: PEdge, inv: { engines: Engine[] }, gateways: Gateway[], modelArmor: ModelArmorResp | null | undefined): IngressInfo {
  const ingress = gateways.filter((g) => g.type === "ingress");
  const engine = edge.caller ? inv.engines.find((e) => e.name === edge.caller) : undefined;
  const gwName = edge.gateway ?? (engine?.gateways.ingress || null);
  const gateway = gwName ? (gateways.find((g) => g.name === gwName) ?? null) : null;
  const ma = gateway ? (modelArmor?.gateways.find((m) => m.gateway === gateway.name) ?? null) : null;
  const ready = (modelArmor?.extensions ?? modelArmor?.setup?.extensions ?? []).length > 0;
  const maAction: IngressInfo["maAction"] = !gateway || !ma ? null : ma.enabled ? { kind: "off", intent: modelArmorFor(gateway, false) } : ready ? { kind: "on", intent: modelArmorFor(gateway, true) } : { kind: "setup" };
  const agents = engine
    ? [engine]
    : edge.source === CLIENT.any || edge.source === CLIENT.ge
      ? inv.engines.filter((e) => (edge.target === NOGW.ingress ? !e.gateways.ingress : e.gateways.ingress === edge.target))
      : [];
  return {
    gateway,
    ma,
    maAction,
    iap: gateway?.authz_policies.find((p) => p.provider === "iap" && p.profile === "REQUEST_AUTHZ") ?? null,
    bound: gateway ? agents.filter((e) => e.gateways.ingress === gateway.name).map((e) => ({ engine: e, unbind: unbindFor(e, gateway) })) : [],
    unbound: agents.filter((e) => !e.gateways.ingress).map((e) => ({ engine: e, why: !e.bindable ? (e.bindable_reason ?? "This agent can't be bound to Agent Gateway.") : !ingress.length ? "No ingress gateway in this region." : null })),
    ingress,
  };
}
