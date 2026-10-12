// Fixed node ids of the policy map, and which pseudo caller draws a member that isn't an engine. Kept apart from
// graph.ts so the "Show on map" links in the other steps can name nodes without pulling the map code into the
// first-load bundle.
import { EVERYONE, PROJECT_AGENTS_RE } from "./evaluate";

export const PSEUDO = { project: "pseudo:project_agents", public: "pseudo:public", other: "pseudo:other", anywhere: "pseudo:anywhere" } as const;
export const NOGW = { egress: "nogw:egress", ingress: "nogw:ingress" } as const;
export const CLIENT = { any: "client:any", ge: "client:ge" } as const;

/** Which pseudo caller draws a binding whose member isn't an engine in the inventory. */
export function pseudoOf(member: string, projectSet: string | null): string {
  if (EVERYONE.includes(member)) return PSEUDO.public;
  if (member === projectSet || PROJECT_AGENTS_RE.test(member)) return PSEUDO.project;
  return PSEUDO.other;
}
