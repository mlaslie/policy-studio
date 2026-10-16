// Private networking (detection only): the audit rules agree with the backend (shared fixture), the mock world has
// every case (N1–N5 across its regions), the map chips, the gateway card's "Private egress" row, and the blocked bind
// of a PSC-interface agent in the mock's preflight.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import cases from "../../../backend/tests/fixtures/networking_cases.json";
import type { Ctx, Engine, Gateway } from "../api/types";
import { buildWorld } from "../api/mockData";
import { audit, gateways as mockGateways, preflight, render } from "../api/mock";
import { buildPolicyGraph } from "../map/graph";
import { nodeHeight } from "../map/layout";
import { StudioProvider } from "../store";
import { PrivateEgressRow } from "../steps/GatewaysStep";
import { PSC_BIND_REASON, auditRules, privateEgressChip, pscChips } from "./networking";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const eng = (ctx: Ctx, name: string) => buildWorld(ctx).inventory.engines.find((e) => e.display_name === name)!;

describe("audit rules N1–N5 shared with the backend", () => {
  it("give exactly the backend's findings (backend/tests/fixtures/networking_cases.json)", () => {
    const got = auditRules(cases.engines as unknown as Engine[], cases.gateways as unknown as Gateway[]);
    expect(got).toEqual(cases.expected);
  });

  it("the mock audit has N1–N5 across its regions, each like the backend would word it", () => {
    const rules = (region: string) => audit({ ...CTX, region }).findings.filter((f) => f.rule);
    const east = rules("us-east4");
    expect(east.map((f) => f.rule).sort()).toEqual(["N1", "N2"]);
    expect(east.find((f) => f.rule === "N1")!.resource).toBe(eng(CTX, "simple-agent-with-psc").name);
    expect(east.find((f) => f.rule === "N2")!.title).toBe("Broken: PSC interface and gateway binding on Ops Copilot");
    expect(rules("us-central1").map((f) => f.rule)).toContain("N3");
    expect(rules("europe-west1").map((f) => f.rule)).toContain("N4");
    expect(rules("us-west1").map((f) => f.rule)).toContain("N5");
    // parity: the mock's findings are the rules applied to the mock's own engines and gateways
    const w = buildWorld(CTX);
    expect(east).toEqual(auditRules(w.inventory.engines, w.gateways));
    // the PSC agent's generic "Unprotected egress" finding is replaced by N1, as on the backend
    expect(audit(CTX).findings.some((f) => f.title === "Unprotected egress: simple-agent-with-psc")).toBe(false);
  });
});

describe("map chips", () => {
  const w = buildWorld(CTX);
  const g = buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "egress" });
  const node = (id: string) => g.nodes.find((n) => n.id === id)!;

  it("gateway: Private egress · VPC, the domains in the tooltip", () => {
    const egress = w.gateways.find((x) => x.type === "egress")!;
    const chip = node(egress.name).chips.find((c) => c.text.startsWith("Private egress"))!;
    expect(chip.text).toBe("Private egress · corp-vpc");
    expect(chip.title).toContain("run.app., corp.internal.");
    expect(chip.title).toContain("Private ranges only");
    const ingress = w.gateways.find((x) => x.type === "ingress")!;
    expect(privateEgressChip(ingress.private_egress)).toBeNull();
  });

  it("agents: red Direct VPC access; Broken as well when bound", () => {
    const psc = node(eng(CTX, "simple-agent-with-psc").name).chips.filter((c) => c.tone === "red").map((c) => c.text);
    expect(psc).toEqual(["Direct VPC access (bypasses gateway)"]);
    const ops = node(eng(CTX, "Ops Copilot").name).chips.filter((c) => c.tone === "red").map((c) => c.text);
    expect(ops).toEqual(["Direct VPC access (bypasses gateway)", "Broken: PSC interface + gateway"]);
    expect(pscChips(eng(CTX, "Helpdesk Agent"))).toEqual([]);
  });

  it("the extra chips are counted in the card height", () => {
    const n = node(eng(CTX, "Ops Copilot").name);
    expect(nodeHeight(n)).toBeGreaterThan(nodeHeight({ ...n, chips: n.chips.filter((c) => c.tone !== "red") }));
  });

  it("the ingress map shows no bypass chip (it's about egress)", () => {
    const gi = buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "ingress" });
    const n = gi.nodes.find((x) => x.id === eng(CTX, "simple-agent-with-psc").name)!;
    expect(n.chips.map((c) => c.text)).not.toContain("Direct VPC access (bypasses gateway)");
    expect(n.chips.find((c) => c.text === "Can't be bound")?.title).toBe(PSC_BIND_REASON);
  });
});

describe("gateway card: Private egress row", () => {
  const row = (gw: Gateway) => renderToStaticMarkup(<StudioProvider><PrivateEgressRow gw={gw} /></StudioProvider>);
  const gws = (region: string) => mockGateways({ ...CTX, region }).gateways;

  it("template: VPC, domain chips, egress mode", () => {
    const html = row(gws("us-east4").find((g) => g.type === "egress")!);
    expect(html).toContain("VPC corp-vpc");
    expect(html).toContain("corp-private");
    expect(html).toContain(">run.app.<");
    expect(html).toContain(">corp.internal.<");
    expect(html).toContain("Private ranges only");
  });

  it("inline, unreadable, public", () => {
    expect(row(gws("us-central1").find((g) => g.type === "egress")!)).toContain("Inline networkConfig");
    expect(row(gws("europe-west1").find((g) => g.type === "egress")!)).toContain("can&#x27;t read details");
    const bare = { ...gws("us-east4").find((g) => g.type === "egress")!, private_egress: null };
    expect(row(bare)).toContain("Public egress only");
    expect(row(gws("us-east4").find((g) => g.type === "ingress")!)).toBe("");
  });
});

describe("preflight: bind of an agent with a PSC interface", () => {
  beforeAll(() => Object.defineProperty(globalThis, "window", { value: { location: { search: "" } }, configurable: true }));
  afterAll(() => Reflect.deleteProperty(globalThis, "window"));
  it("is blocked in the mock, with the plan's message; render refuses it too", () => {
    const w = buildWorld(CTX);
    const egress = w.gateways.find((x) => x.type === "egress")!.name;
    const psc = eng(CTX, "simple-agent-with-psc");
    const intent = { id: "b", kind: "bind_gateway" as const, engine: psc.name, gateway: { name: egress, direction: "egress" as const } };
    const item = preflight(CTX, [intent]).items[0];
    expect(item).toMatchObject({ status: "blocked", fix: "redeploy" });
    expect(item.reason).toBe(`simple-agent-with-psc can't be bound to Agent Gateway. ${PSC_BIND_REASON}`);
    expect(render(CTX, [intent]).items[0].error).toContain(PSC_BIND_REASON);
  });
});
