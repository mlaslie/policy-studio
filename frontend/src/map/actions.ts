// What the policy panel stages (docs/VISUALIZATION_PLAN.md §9): intents built from a line's reasons, never written
// directly. Pure, so the exact intents are tested.
import type { Access, Engine, Gateway, Grant, Intent } from "../api/types";
import { grantToIntent, grantToModify, grantToRevoke } from "../lib/grants";
import { conditionFor, newId, shortName } from "../lib/policy";
import type { PNode, Reason } from "./graph";
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

/** Bind an agent with no gateway to an egress gateway. */
export const bindFor = (engine: Pick<Engine, "name" | "display_name">, gw: Pick<Gateway, "name">): Intent => ({
  id: newId(),
  kind: "bind_gateway",
  gateway: { name: gw.name, direction: "egress" },
  engine: engine.name,
  engine_label: engine.display_name,
});
