// The map step's badge (§2): the cart items the staged-change view draws, counted without the graph code; the kinds
// it counts are exactly the ones simulate.ts applies.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Intent, IntentKind } from "../api/types";
import { simulate } from "../map/simulate";
import { MAP_KINDS, mapBadge, mapPendingCount } from "./mapBadge";

const w = buildWorld({ project: "my-demo-project", region: "us-east4" });
const hd = w.inventory.engines[0];
const egress = w.gateways.find((g) => g.type === "egress")!;
const tickets = w.inventory.mcp_servers[0];
const src = { type: "engine" as const, principal: hd.principal, label: hd.display_name, engine: hd.name };
const dst = { kind: "mcp_server" as const, id: tickets.id, name: tickets.name, label: tickets.display_name };
const one: Record<IntentKind, Intent> = {
  grant: { id: "grant", kind: "grant", source: src, destination: dst, access: { mode: "all" } },
  revoke: { id: "revoke", kind: "revoke", source: src, destination: dst },
  modify: { id: "modify", kind: "modify", source: src, destination: dst, access_from: { mode: "all" }, access: { mode: "read_only_hint" } },
  bind_gateway: { id: "bind_gateway", kind: "bind_gateway", engine: w.inventory.engines[2].name, gateway: { name: egress.name, direction: "egress" } },
  unbind_gateway: { id: "unbind_gateway", kind: "unbind_gateway", engine: hd.name, gateway: { name: egress.name, direction: "egress" } },
  set_enforcement: { id: "set_enforcement", kind: "set_enforcement", gateway: { name: egress.name, direction: "egress" }, extension: egress.enforcement!.extension, mode: "ENFORCE", scope: "shared" },
  model_armor_on: { id: "model_armor_on", kind: "model_armor_on", gateway: { name: w.gateways[1].name, direction: "ingress" } },
  model_armor_off: { id: "model_armor_off", kind: "model_armor_off", gateway: { name: egress.name, direction: "egress" } },
  model_armor_template: { id: "model_armor_template", kind: "model_armor_template", params: { template_id: "x" } },
  model_armor_extension: { id: "model_armor_extension", kind: "model_armor_extension", params: { name: "x" } },
  iam_project_grant: { id: "iam_project_grant", kind: "iam_project_grant", params: { member: "x", roles: [] } },
  dedicate_extension: { id: "dedicate_extension", kind: "dedicate_extension", gateway: { name: egress.name, direction: "egress" }, new_name: "x" },
};

describe("map step badge", () => {
  it("counts the cart items the map draws; none for an empty cart or setup-only items", () => {
    expect(mapBadge([])).toBeNull();
    expect(mapBadge([one.model_armor_template, one.iam_project_grant])).toBeNull();
    expect(mapPendingCount([one.grant, one.model_armor_template, one.unbind_gateway, one.model_armor_on])).toBe(3);
    expect(mapBadge([one.grant, one.modify])).toEqual({ text: "2", tone: "amber", title: "2 staged changes on the map" });
    expect(mapBadge([one.revoke])?.title).toBe("1 staged change on the map");
  });

  it("counts exactly the kinds the staged-change view applies (simulate.ts)", () => {
    const sim = simulate({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor }, Object.values(one));
    const drawn = Object.keys(sim.effects).sort();
    expect(drawn).toEqual([...MAP_KINDS].sort());
    expect(sim.ignored.sort()).toEqual(Object.keys(one).filter((k) => !MAP_KINDS.has(k as IntentKind)).sort());
  });
});
