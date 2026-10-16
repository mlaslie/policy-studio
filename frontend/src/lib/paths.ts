// "Seen in traffic" path labels for destinations (docs/PRIVATE_NETWORKING_PLAN.md §8, phase N-4): from
// GET /destination-paths, the calls through the egress gateways that reached a private upstream address versus a
// public one. Pure; shared by Inventory, the policy map's destination chips and the policy panel's Path row.
import type { DestinationPath, DestinationPathsResp, PathCounts, PathKind } from "../api/types";
import { plural } from "./util";

export const PATH_TEXT: Record<PathKind, string> = {
  private: "Private (seen in traffic)",
  public: "Public (seen in traffic)",
  mixed: "Mixed paths",
};
export const PATH_TONE: Record<PathKind, "blue" | "neutral" | "amber"> = { private: "blue", public: "neutral", mixed: "amber" };
/** The map card's short chip (private and mixed only: public is the default and would only add noise). */
export const PATH_CHIP: Partial<Record<PathKind, string>> = { private: "Private", mixed: "Mixed paths" };

const MIXED_NOTE = "Reached at both private and public addresses: usually several hostnames (only some resolve into the VPC) or a DNS change inside the window.";

/** private when some call reached a private address and none a public one; public the other way round; mixed for
 *  both; null when there were no such calls (no label). */
export function pathKind(c: Pick<PathCounts, "private" | "public"> | null | undefined): PathKind | null {
  if (!c) return null;
  if (c.private > 0 && c.public > 0) return "mixed";
  return c.private > 0 ? "private" : c.public > 0 ? "public" : null;
}

/** "7d" → "the last 7 days", "24h" → "the last 24 hours". */
export function windowText(w: string | undefined): string {
  const m = /^(\d+)([mhd])$/.exec(w ?? "");
  if (!m) return "the window";
  const n = Number(m[1]);
  const unit = { m: "minute", h: "hour", d: "day" }[m[2] as "m" | "h" | "d"];
  return n === 1 ? `the last ${unit}` : `the last ${n} ${unit}s`;
}

/** "2026-10-14 18:12 UTC" (fixed format and zone: the same in every browser and test). */
export function seenAt(iso: string | null | undefined): string {
  if (!iso) return "never";
  const d = new Date(iso);
  return isNaN(+d) ? iso : `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** The tooltip: counts, the window and the last time seen (and, for a mixed path, why it happens). */
export function pathTip(c: PathCounts & { hosts?: string[] }, window: string): string {
  const k = pathKind(c);
  const lines = [
    `${plural(c.private, "private call")}, ${plural(c.public, "public call")} in ${windowText(window)}${c.unknown ? ` (${c.unknown} to other addresses)` : ""}; last seen ${seenAt(c.last_seen)}.`,
    "From the gateway request logs (httpRequest.serverIp, the address the gateway connected to).",
  ];
  if (k === "mixed") lines.push(MIXED_NOTE);
  if (c.hosts?.length) lines.push(`Hosts: ${c.hosts.join(", ")}`);
  return lines.join("\n");
}

export type PathLabel = { kind: PathKind; text: string; tone: "blue" | "neutral" | "amber"; tip: string };

/** The label for a destination, or null when no call was seen (nothing is shown). */
export function pathLabel(c: (PathCounts & { hosts?: string[] }) | null | undefined, window: string): PathLabel | null {
  const kind = pathKind(c);
  if (!c || !kind) return null;
  return { kind, text: PATH_TEXT[kind], tone: PATH_TONE[kind], tip: pathTip(c, window) };
}

/** Several destinations as one (the map's collapsed Google APIs group): counts added, the latest times kept. */
export function mergePaths(cs: (DestinationPath | null | undefined)[]): DestinationPath | null {
  const xs = cs.filter((c): c is DestinationPath => !!c);
  if (!xs.length) return null;
  const latest = (vs: (string | null)[]) => vs.reduce<string | null>((a, b) => (b && (!a || b > a) ? b : a), null);
  const by: Record<string, PathCounts> = {};
  for (const x of xs)
    for (const [g, c] of Object.entries(x.by_gateway ?? {})) {
      const m = (by[g] ??= { private: 0, public: 0, unknown: 0, last_seen: null });
      m.private += c.private;
      m.public += c.public;
      m.unknown += c.unknown;
      m.last_seen = latest([m.last_seen, c.last_seen]);
    }
  const out: DestinationPath = {
    private: xs.reduce((a, x) => a + x.private, 0),
    public: xs.reduce((a, x) => a + x.public, 0),
    unknown: xs.reduce((a, x) => a + x.unknown, 0),
    last_seen: latest(xs.map((x) => x.last_seen)),
    last_private: latest(xs.map((x) => x.last_private)),
    last_public: latest(xs.map((x) => x.last_public)),
    hosts: [...new Set(xs.flatMap((x) => x.hosts))].slice(0, 5),
    by_gateway: by,
    path: null,
  };
  out.path = pathKind(out);
  return out;
}

/** A destination's counts: over every gateway, or through one gateway (a map line's). undefined = traffic not read;
 *  null = no calls. */
export function pathThrough(p: DestinationPath | null | undefined, gateway?: string | null): (PathCounts & { hosts?: string[] }) | null | undefined {
  if (!p || !gateway) return p;
  const g = p.by_gateway?.[gateway];
  return g ? { ...g, hosts: p.hosts } : null;
}

/** The policy panel's Path row text next to the label: the counts, the window and the last time seen, or why there's
 *  no label. */
export function pathRow(c: (PathCounts & { hosts?: string[] }) | null | undefined, window: string | undefined): string {
  if (c === undefined) return "Traffic not read yet";
  const l = pathLabel(c, window ?? "7d");
  if (!c || !l) return `No calls seen in ${windowText(window)}`;
  return `${plural(c.private, "private call")}, ${plural(c.public, "public call")} in ${windowText(window)}; last seen ${seenAt(c.last_seen)}`;
}

/** A destination's path in a paths response (Inventory). undefined = not read; null = no calls. */
export const pathOf = (paths: DestinationPathsResp | null | undefined, dest: string): DestinationPath | null | undefined => (paths ? (paths.destinations[dest] ?? null) : undefined);
