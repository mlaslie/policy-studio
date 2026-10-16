// "Seen in traffic" path labels (phase N-4): which label a destination gets, the map chip and the Inventory badge,
// and the mock's port of gcp/paths.py against the backend's shared fixture.
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import cases from "../../../backend/tests/fixtures/path_cases.json";
import type { Ctx, DestinationPath } from "../api/types";
import { buildWorld } from "../api/mockData";
import { aggregate, classifyIp, destinationPaths } from "../api/mockPaths";
import { destinationPaths as mockEndpoint } from "../api/mock";
import { buildPolicyGraph, pathChip } from "../map/graph";
import { chipShown, nodeHeight } from "../map/layout";
import { PathBadge } from "../components/PathBadge";
import { mergePaths, pathKind, pathLabel, pathRow, pathThrough, pathTip, seenAt, windowText } from "./paths";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const NOW = Date.parse("2026-10-15T12:00:00Z");
const counts = (priv: number, pub: number, extra: Partial<DestinationPath> = {}): DestinationPath => ({
  private: priv,
  public: pub,
  unknown: 0,
  last_seen: "2026-10-14T18:12:30.323Z",
  last_private: priv ? "2026-10-14T18:12:30.323Z" : null,
  last_public: pub ? "2026-10-13T08:00:00Z" : null,
  hosts: ["tickets.example.com"],
  by_gateway: {},
  path: pathKind({ private: priv, public: pub }),
  ...extra,
});

describe("label selection", () => {
  it("private when a private call was seen and no public one, public the other way round, mixed for both, none for no calls", () => {
    expect(pathKind(counts(3, 0))).toBe("private");
    expect(pathKind(counts(0, 5))).toBe("public");
    expect(pathKind(counts(1, 1))).toBe("mixed");
    expect(pathKind(counts(0, 0))).toBeNull();
    expect(pathKind({ ...counts(0, 0), unknown: 4 })).toBeNull(); // only the platform's own addresses
    expect(pathKind(null)).toBeNull();
    expect(pathLabel(counts(3, 0), "7d")).toMatchObject({ kind: "private", text: "Private (seen in traffic)", tone: "blue" });
    expect(pathLabel(counts(0, 5), "7d")).toMatchObject({ kind: "public", text: "Public (seen in traffic)", tone: "neutral" });
    expect(pathLabel(counts(1, 1), "7d")).toMatchObject({ kind: "mixed", text: "Mixed paths", tone: "amber" });
    expect(pathLabel(counts(0, 0), "7d")).toBeNull();
    expect(pathLabel(undefined, "7d")).toBeNull();
  });

  it("the tooltip has the counts, the window and the last time seen; mixed says why", () => {
    const tip = pathTip(counts(3, 0), "7d");
    expect(tip).toContain("3 private calls, 0 public calls in the last 7 days; last seen 2026-10-14 18:12 UTC.");
    expect(tip).toContain("httpRequest.serverIp");
    expect(tip).not.toContain("several hostnames");
    const mixed = pathTip(counts(1, 2, { hosts: ["a.run.app", "b.run.app"] }), "24h");
    expect(mixed).toContain("1 private call, 2 public calls in the last 24 hours");
    expect(mixed).toContain("several hostnames");
    expect(mixed).toContain("Hosts: a.run.app, b.run.app");
    expect(windowText("1d")).toBe("the last day");
    expect(seenAt(null)).toBe("never");
  });

  it("a map line's Path row counts only its own gateway", () => {
    const p = counts(2, 1, { by_gateway: { "gw/a": { private: 2, public: 0, unknown: 0, last_seen: "2026-10-14T00:00:00Z" } } });
    expect(pathKind(pathThrough(p, "gw/a"))).toBe("private"); // mixed overall, private through gw/a
    expect(pathThrough(p, "gw/b")).toBeNull();
    expect(pathThrough(p, null)).toBe(p);
    expect(pathThrough(undefined, "gw/a")).toBeUndefined();
    expect(pathRow(pathThrough(p, "gw/a"), "7d")).toBe("2 private calls, 0 public calls in the last 7 days; last seen 2026-10-14 00:00 UTC");
    expect(pathRow(null, "7d")).toBe("No calls seen in the last 7 days");
    expect(pathRow(undefined, "7d")).toBe("Traffic not read yet");
  });

  it("the Google APIs group adds its endpoints up", () => {
    expect(mergePaths([counts(0, 4), counts(0, 2), null])).toMatchObject({ private: 0, public: 6, path: "public" });
    expect(mergePaths([counts(0, 4), counts(1, 0)])?.path).toBe("mixed");
    expect(mergePaths([null, undefined])).toBeNull();
  });
});

describe("chips and badges", () => {
  it("map chip: a lock and Private, or Mixed paths; none for public only or no calls", () => {
    expect(pathChip(counts(3, 0), "7d")).toMatchObject({ text: "Private", tone: "blue", icon: "lock" });
    expect(pathChip(counts(3, 0), "7d")!.title).toContain("Private (seen in traffic)\n3 private calls");
    expect(pathChip(counts(1, 1), "7d")).toMatchObject({ text: "Mixed paths", tone: "amber" });
    expect(pathChip(counts(1, 1), "7d")!.icon).toBeUndefined();
    expect(pathChip(counts(0, 9), "7d")).toBeNull();
    expect(pathChip(null, "7d")).toBeNull();
  });

  it("the lock is counted in the chip's room (the card height stays right)", () => {
    const long = { text: "Private private private private private private", tone: "blue" as const };
    expect(chipShown({ ...long, icon: "lock" }, "mcp").text.length).toBeLessThan(chipShown(long, "mcp").text.length);
  });

  it("Inventory badge: label and lock, counts in the tooltip; nothing without calls", () => {
    const html = renderToStaticMarkup(<PathBadge path={counts(3, 0)} window="7d" />);
    expect(html).toContain("Private (seen in traffic)");
    expect(html).toContain("<svg");
    expect(html).toContain('data-path="private"');
    expect(html).toContain("3 private calls, 0 public calls in the last 7 days");
    const pub = renderToStaticMarkup(<PathBadge path={counts(0, 2)} window="7d" />);
    expect(pub).toContain("Public (seen in traffic)");
    expect(pub).not.toContain("<svg");
    expect(renderToStaticMarkup(<PathBadge path={counts(2, 2)} window="7d" />)).toContain("Mixed paths");
    expect(renderToStaticMarkup(<PathBadge path={null} window="7d" />)).toBe("");
    expect(renderToStaticMarkup(<PathBadge path={undefined} window="7d" />)).toBe("");
  });
});

describe("mock parity with the backend (backend/tests/fixtures/path_cases.json)", () => {
  it.each(cases.ips as [string, string][])("classifies %s as %s", (ip, want) => {
    expect(classifyIp(ip)).toBe(want);
  });

  it("aggregates the fixture's entries to the backend's result", () => {
    const got = aggregate(cases.entries as Parameters<typeof aggregate>[0], "gw");
    const pick = (c: DestinationPath) => ({ private: c.private, public: c.public, unknown: c.unknown, last_seen: c.last_seen, path: c.path, hosts: c.hosts });
    expect(Object.fromEntries(Object.entries(got).map(([k, v]) => [k, pick(v)]))).toEqual(cases.expected);
  });

  it("the mock world: Tickets MCP private through the template gateway, HR Directory MCP public, Knowledge Base Agent mixed", () => {
    const w = buildWorld(CTX);
    const r = destinationPaths(w, "7d", NOW);
    const id = (coll: { id: string; name: string }[], x: string) => coll.find((e) => e.id === x)!.name;
    const egress = w.gateways.find((g) => g.type === "egress")!;
    expect(egress.private_egress?.source).toBe("template");
    const tickets = r.destinations[id(w.inventory.mcp_servers, "tickets-mcp-6a21")];
    expect(tickets.path).toBe("private");
    expect(Object.keys(tickets.by_gateway)).toEqual([egress.name]);
    expect(r.destinations[id(w.inventory.mcp_servers, "hr-directory-mcp-0f3c")].path).toBe("public");
    const kb = r.destinations[id(w.inventory.agents, "kb-agent-4c1e")];
    expect(kb.path).toBe("mixed");
    expect(kb.last_private! > kb.last_public!).toBe(true); // private since the DNS change
    expect(r.destinations[id(w.inventory.endpoints, "aiplatform-googleapis")].path).toBe("public");
    expect(r.destinations[id(w.inventory.agents, "billing-agent-91d0")]).toBeUndefined(); // denied only: no serverIp
    expect(r.gateways).toEqual([expect.objectContaining({ gateway: egress.name, private_egress: true, truncated: false })]);
    expect(r.notes.some((n) => n.startsWith("Mixed paths"))).toBe(true);
    // a shorter window drops the older public calls: Knowledge Base Agent is private only over the last day
    expect(destinationPaths(w, "24h", NOW).destinations[id(w.inventory.agents, "kb-agent-4c1e")].path).toBe("private");
    expect(destinationPaths(w, "90d", NOW).window).toBe("30d");
    expect(mockEndpoint(CTX).window).toBe("7d");
  });

  it("on the map: the chip on the private and mixed destinations only, counted in their height; none on the ingress map", () => {
    const w = buildWorld(CTX);
    const paths = destinationPaths(w, "7d", NOW);
    const g = buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "egress", paths });
    const without = buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "egress" });
    const node = (gr: typeof g, x: string) => gr.nodes.find((n) => n.id.endsWith(`/${x}`))!;
    const chipOf = (x: string) => node(g, x).chips.find((c) => c.text === "Private" || c.text === "Mixed paths");
    expect(chipOf("tickets-mcp-6a21")).toMatchObject({ text: "Private", icon: "lock" });
    expect(chipOf("kb-agent-4c1e")?.text).toBe("Mixed paths");
    expect(chipOf("hr-directory-mcp-0f3c")).toBeUndefined();
    expect(chipOf("aiplatform-googleapis")).toBeUndefined();
    expect(node(g, "tickets-mcp-6a21").path?.path).toBe("private");
    expect(node(g, "billing-agent-91d0").path).toBeNull(); // read, no calls
    expect(node(without, "tickets-mcp-6a21").path).toBeUndefined(); // not read
    expect(nodeHeight(node(g, "tickets-mcp-6a21"))).toBeGreaterThan(nodeHeight(node(without, "tickets-mcp-6a21")));
    const gi = buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "ingress", paths });
    expect(gi.nodes.some((n) => n.chips.some((c) => c.icon === "lock"))).toBe(false);
  });
});
