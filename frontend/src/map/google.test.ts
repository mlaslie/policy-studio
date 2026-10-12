// Google API endpoints on the policy map: one collapsed "Google APIs (N)" node, its lines, the "Show Google API
// endpoints" checkbox, search into the group, the table, and endpoint labels (labels.ts).
import { describe, expect, it } from "vitest";
import { PLATFORM_PREFIX, buildWorld } from "../api/mockData";
import type { Ctx } from "../api/types";
import { PSEUDO, buildPolicyGraph, type GraphInput } from "./graph";
import { DEFAULT_FILTERS, GOOGLE_GROUP, expandGroup, mergeIntoGroup, revealPatch, tableRows, viewOf, type MapFilters } from "./view";
import { endpointLabel, hostOf, isGoogleApi, middleEllipsis, shortLabel } from "./labels";
import { layoutView } from "./layout";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const w0 = buildWorld(CTX);
const inv = w0.inventory;
const input = (extra: Partial<GraphInput> = {}): GraphInput => ({ inventory: inv, gateways: w0.gateways, modelArmor: w0.modelArmor, direction: "egress", ...extra });
const filters = (f: Partial<MapFilters> = {}): MapFilters => ({ ...DEFAULT_FILTERS, ...f });
const eng = (name: string) => inv.engines.find((e) => e.display_name === name)!;
const ep = (displayName: string) => inv.endpoints.find((e) => e.display_name === displayName)!;
const google = inv.endpoints.filter((e) => isGoogleApi(e.url));
const g = buildPolicyGraph(input());

describe("labels", () => {
  it("hostOf keeps a port that's written out, lowercase", () => {
    expect(hostOf("https://CloudTrace.mtls.googleapis.com:443/v2")).toBe("cloudtrace.mtls.googleapis.com:443");
    expect(hostOf("https://cloudtrace.googleapis.com")).toBe("cloudtrace.googleapis.com");
    expect(hostOf("not a url")).toBeNull();
  });

  it("isGoogleApi: *.googleapis.com, any port", () => {
    expect(isGoogleApi("https://iamcredentials.mtls.googleapis.com:443")).toBe(true);
    expect(isGoogleApi("https://aiplatform.us-east4.rep.googleapis.com")).toBe(true);
    expect(isGoogleApi("https://api.weather.example.com/v1")).toBe(false);
    expect(isGoogleApi("https://googleapis.com.example.net")).toBe(false);
  });

  it("drops a display-name prefix that only repeats the host, keeps the port, keeps a chosen name", () => {
    expect(endpointLabel("acme-prod cloudtrace.googleapis.com", "https://cloudtrace.googleapis.com")).toBe("cloudtrace.googleapis.com");
    expect(endpointLabel("acme-prod cloudtrace.mtls.googleapis.com:443", "https://cloudtrace.mtls.googleapis.com:443")).toBe("cloudtrace.mtls.googleapis.com:443");
    // the display name ends with the host but the URL has a port: the port is kept
    expect(endpointLabel("acme-prod logging.mtls.googleapis.com", "https://logging.mtls.googleapis.com:443")).toBe("logging.mtls.googleapis.com:443");
    expect(endpointLabel("cloudtrace.googleapis.com", "https://cloudtrace.googleapis.com")).toBe("cloudtrace.googleapis.com");
    expect(endpointLabel("", "https://sts.googleapis.com")).toBe("sts.googleapis.com");
    expect(endpointLabel("Weather API", "https://api.weather.example.com/v1")).toBe("Weather API");
  });

  it("shortens from the middle so the service name and the port both show", () => {
    expect(middleEllipsis("iamcredentials.mtls.googleapis.com:443", 32)).toBe("iamcredentials.mtls…apis.com:443");
    expect(middleEllipsis("sts.googleapis.com", 32)).toBe("sts.googleapis.com");
    const a = middleEllipsis("cloudresourcemanager.mtls.googleapis.com", 32);
    const b = middleEllipsis("cloudresourcemanager.mtls.googleapis.com:443", 32);
    expect(a).toHaveLength(32);
    expect(a).not.toBe(b);
    expect(b.endsWith(":443")).toBe(true);
  });

  it("card titles: the domain is elided first, so every platform host stays distinct and keeps .mtls and the port", () => {
    expect(shortLabel("iamcredentials.mtls.googleapis.com:443", 32)).toBe("iamcredentials.mtls…apis.com:443");
    expect(shortLabel("sts.mtls.googleapis.com", 32)).toBe("sts.mtls.googleapis.com");
    const hosts = inv.endpoints.filter((e) => isGoogleApi(e.url)).map((e) => endpointLabel(e.display_name, e.url));
    const short = hosts.map((h) => shortLabel(h, 32));
    expect(short.every((s) => s.length <= 32)).toBe(true);
    expect(new Set(short).size).toBe(new Set(hosts).size);
    const crm = ["cloudresourcemanager.googleapis.com", "cloudresourcemanager.mtls.googleapis.com", "cloudresourcemanager.mtls.googleapis.com:443"].map((h) => shortLabel(h, 32));
    expect(new Set(crm).size).toBe(3);
    expect(crm[1]).toContain("mtls");
    expect(crm[2].endsWith(":443")).toBe(true);
    // not a host: plain middle ellipsis
    expect(shortLabel("acme-prod cloudresourcemanager.mtls.googleapis.com", 33)).toBe(middleEllipsis("acme-prod cloudresourcemanager.mtls.googleapis.com", 33));
  });

  it("endpoint nodes: host title, the display name as sub, full name and URL kept for hover and details", () => {
    const n = g.nodes.find((x) => x.id === ep(`${PLATFORM_PREFIX} iamcredentials.mtls.googleapis.com:443`).name)!;
    expect(n).toMatchObject({ label: "iamcredentials.mtls.googleapis.com:443", sub: `${PLATFORM_PREFIX} iamcredentials.mtls.googleapis.com:443`, url: "https://iamcredentials.mtls.googleapis.com:443", googleApi: true });
    const labels = g.nodes.filter((x) => x.kind === "endpoint" && x.googleApi).map((x) => x.label);
    expect(new Set(labels).size).toBe(labels.length); // every card title is distinct
    expect(g.nodes.find((x) => x.id === ep("Weather API").name)).toMatchObject({ label: "Weather API", googleApi: false });
  });
});

describe("the Google APIs group", () => {
  it("is collapsed by default: one node with every shown Google API endpoint, other endpoints untouched", () => {
    expect(DEFAULT_FILTERS.googleApis).toBe(false);
    const v = viewOf(g, filters(), null);
    const grp = v.nodes.find((n) => n.id === GOOGLE_GROUP)!;
    expect(google.length).toBe(38);
    expect(grp).toMatchObject({ kind: "google_apis", label: "Google APIs (38)", section: "api", column: "dests" });
    expect(new Set(grp.grouped)).toEqual(new Set(google.map((e) => e.name)));
    expect(v.nodes.some((n) => n.kind === "endpoint" && n.googleApi)).toBe(false);
    // Weather API (a grant) is on the map; Partner payments (no grants) is in the "no grants" group, not this one
    expect(v.nodes.some((n) => n.id === ep("Weather API").name)).toBe(true);
    expect(v.nodes.find((n) => n.id === "group:api")?.grouped).toEqual([ep("Partner payments").name]);
    // the unreadable Cloud SQL Admin API is inside it, flagged on the group
    expect(grp.chips.map((c) => c.text)).toContain("1 IAP policy couldn't be read");
    expect(grp.sub).toBe("16 with grants · click to show them");
  });

  it("merges its lines per source: the combined verdict and the count", () => {
    const v = viewOf(g, filters(), null);
    const into = v.edges.filter((e) => e.target === GOOGLE_GROUP);
    expect(into).toHaveLength(1);
    expect(into[0]).toMatchObject({ source: PSEUDO.project, verdict: "allowed", label: "16 APIs" });
    expect(into[0].members).toHaveLength(16);
    expect(into[0].reasons).toHaveLength(16);
    expect(v.edges.some((e) => google.some((x) => x.name === e.target))).toBe(false);
  });

  it("the checkbox shows them one by one; clicking the group ticks it", () => {
    const grp = viewOf(g, filters(), null).nodes.find((n) => n.id === GOOGLE_GROUP)!;
    expect(expandGroup(grp, filters())).toEqual({ googleApis: true });
    const v = viewOf(g, filters(expandGroup(grp, filters())), null);
    expect(v.nodes.some((n) => n.id === GOOGLE_GROUP)).toBe(false);
    expect(v.edges.filter((e) => e.source === PSEUDO.project)).toHaveLength(16);
    // a "no grants" group still expands its section
    expect(expandGroup({ kind: "endpoint_group", section: "api" }, filters({ expanded: ["mcp"] }))).toEqual({ expanded: ["mcp", "api"] });
  });

  it("follows the APIs type filter", () => {
    const v = viewOf(g, filters({ types: { ...DEFAULT_FILTERS.types, api: false } }), null);
    expect(v.nodes.some((n) => n.id === GOOGLE_GROUP || n.kind === "endpoint")).toBe(false);
  });

  it("selected agent: one inherited line and one default-deny line into the group, with counts", () => {
    const hd = eng("Helpdesk Agent");
    const gf = buildPolicyGraph(input({ focus: hd.name }));
    const v = viewOf(gf, filters(), hd.name);
    const into = v.edges.filter((e) => e.target === GOOGLE_GROUP);
    expect(into).toHaveLength(2);
    const granted = into.find((e) => !e.implicit)!;
    const denied = into.find((e) => e.implicit)!;
    expect(granted).toMatchObject({ verdict: "allowed", inherited: true, caller: hd.name, label: "16 APIs" });
    // 38 Google APIs: 16 granted project-wide, 1 unreadable (no line guessed), 21 denied by default (dry run)
    expect(denied).toMatchObject({ verdict: "would_deny", caller: hd.name, label: "21 APIs" });
    expect(gf.focusLines!.filter((l) => l.implicit && google.some((x) => x.name === l.target))).toHaveLength(21);
    // without implicit denies, only the granted line
    expect(viewOf(gf, filters({ implicit: false }), hd.name).edges.filter((e) => e.target === GOOGLE_GROUP)).toHaveLength(1);
  });

  it("the table lists every endpoint behind a merged line", () => {
    const rows = tableRows(viewOf(g, filters(), null)).filter((r) => r.source === PSEUDO.project);
    expect(rows).toHaveLength(16);
    expect(new Set(rows.map((r) => r.target)).size).toBe(16);
    expect(rows.every((r) => g.nodes.find((n) => n.id === r.target)?.googleApi)).toBe(true);
  });

  it("is laid out like a destination (in the API endpoints section)", () => {
    const v = viewOf(g, filters(), null);
    const l = layoutView(v);
    expect(l.pos[GOOGLE_GROUP]).toBeDefined();
    expect(l.headers.some((h) => h.label === "API endpoints")).toBe(true);
  });

  it("mergeIntoGroup keeps other lines and marks a mixed staged group as a change", () => {
    const base = { direction: "egress" as const, reasons: [], source: "s" };
    const out = mergeIntoGroup(
      [
        { ...base, id: "1", target: "a", verdict: "allowed", pending: "add" },
        { ...base, id: "2", target: "b", verdict: "conditional" },
        { ...base, id: "3", target: "other", verdict: "allowed" },
      ],
      new Set(["a", "b"]),
      GOOGLE_GROUP,
    );
    expect(out.map((e) => e.target)).toEqual(["other", GOOGLE_GROUP]);
    expect(out[1]).toMatchObject({ verdict: "allowed", label: "2 APIs", pending: "change" });
  });
});

describe("search inside the group", () => {
  it("finds an individual entry and expands the group to show it", () => {
    const q = "iamcredentials";
    const matches = g.nodes.filter((n) => n.search.includes(q));
    expect(matches.length).toBeGreaterThanOrEqual(3);
    const target = matches.find((n) => n.label === "iamcredentials.mtls.googleapis.com:443")!;
    const v = viewOf(g, filters(), null);
    expect(v.nodes.find((n) => n.id === GOOGLE_GROUP)?.search).toContain(q);
    expect(revealPatch(g, filters(), null, target.id)).toEqual({ googleApis: true });
    expect(viewOf(g, filters({ googleApis: true }), null).nodes.some((n) => n.id === target.id)).toBe(true);
  });

  it("an entry with no grants: the group, then its \"no grants\" group", () => {
    const iam = ep("IAM Credentials API").name; // no grants
    const patch = revealPatch(g, filters(), null, iam)!;
    expect(patch).toEqual({ googleApis: true, expanded: ["api"] });
    expect(viewOf(g, filters(patch), null).nodes.some((n) => n.id === iam)).toBe(true);
  });

  it("nothing to expand when it's shown, null when another filter hides it", () => {
    expect(revealPatch(g, filters(), null, ep("Weather API").name)).toEqual({});
    expect(revealPatch(g, filters({ types: { ...DEFAULT_FILTERS.types, api: false } }), null, ep("Weather API").name)).toBeNull();
  });

  it("a selected Google API endpoint stays on its own", () => {
    const id = ep(`${PLATFORM_PREFIX} sts.googleapis.com`).name;
    const v = viewOf(g, filters(), id);
    expect(v.nodes.some((n) => n.id === id)).toBe(true);
    expect(v.nodes.find((n) => n.id === GOOGLE_GROUP)?.grouped).not.toContain(id);
  });
});
