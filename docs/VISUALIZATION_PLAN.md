# Policy Studio: Policy Map (visualization plan)

Status: implemented, phases 0–6 of [§15](#15-phases-rough-sizes): [phase 0 and 0b](#15-phases-rough-sizes) (step keys, the map as step 1, the `modify` intent) in 833d824, phases 1–2 (graph, canvas, filters, table view) in ddf9186, phases 3–4 (policy panel, actions, staged view, saved positions) in 10bd7f5, and phases 5–6 (Client-to-Agent actions, the us-west1 scale scenario, performance, docs) after it. The optional phases 7 and 8 aren't started. **Redesign (2026-10-12):** lines only for selected agents, each agent's own (never combined), the object picker in place of search and the type checkboxes, Show: Allows / Denies, and Reset view; see [§5.4](#54-redesign-2026-10-12-lines-only-for-selected-agents-the-object-picker). Scope: the frontend (`frontend/src`) plus one backend addition (`modify`). Every change still goes through the cart, then Review, then Apply.

## 1. Goal

An interactive map you can zoom, pan and drag that shows **who can reach what, and why**. Every node and every line comes from policy state that Policy Studio already reads:

| On the map | Source (docs/API.md) |
|---|---|
| Agent Runtime agents (callers) | `Inventory.engines[]` (`principal`, `identity_type`, `gateways.{egress,ingress}`, `bindable`) |
| A2A agents, Agent Runtime agents as destinations | `Inventory.agents[]` (`kind: "a2a" \| "runtime"`, `engine`, `skills`) |
| MCP servers and their tools | `Inventory.mcp_servers[]` (`tools[].read_only`, `destructive`) |
| API endpoints | `Inventory.endpoints[]` |
| Allow lines | `Inventory.access[resource]` and `Inventory.access["projects/<P>/locations/<R>"]` (registry-wide): `roles/iap.egressor` bindings, `condition`, `english` |
| Gateways | `/gateways`: `type`, `governed_access_path` (`AGENT_TO_ANYWHERE` / `CLIENT_TO_AGENT`), `bound_engines`, `authz_policies`, `enforcement.mode` (`ENFORCE` / `DRY_RUN`), `enforcement.shared_with` |
| Model Armor | `/model-armor`: `gateways[].enabled`, `template` (filters, summary), CONTENT_AUTHZ `enforcement` |
| "All agents in project" | `/context.principal_set`, `Inventory.project_agents_principal` |
| Staged changes | the cart (`Intent[]` in the store) |

Nothing comes from a theme file. The canvas look (nodes, lines, line styles, particles, shield, legend) is ported from the sibling demo's `ui/frontend/src/diagram/*`, which is already built on `@xyflow/react`.

## 2. Where it lives and how you get there

**Decision (2026-10-12): the map is step 1, right after Context** (key `map`, title "Policy map", subtitle "Who can reach what"). After picking a project and region, the first thing you see is the whole picture. The later steps are where you look at details and make changes.

New order: `0 Context → 1 Policy map → 2 Gateways → 3 Model Armor → 4 Inventory → 5 Build → 6 Review → 7 Apply → 8 Audit`.

- **Renumbering:** every later step moves up by one. Hard-coded step numbers would need updating everywhere: `goto(n)`, `openBuilder` (→5), `openReview` (→6), `openApply` (→7), `openMaSetup` (→3), the badges in `App.tsx`, the stepper footer and any copy that says "step N".
  - Fix this once, in Phase 0: look steps up by key (`goto("apply")` / a `stepN("apply")` helper) instead of by number, so later reordering is free.
  - Add a test that every `goto` target exists.
  - Saved state that holds a step number (localStorage `studio.step`, if present) is moved to the key on load.
- After Context's "Continue" (and on load with a saved context), go to the map.
- **Full-bleed layout:** when the step key is `map`, `main.center` gets a `center-wide` class (no `max-width: 1080px` on `.center-inner`). The canvas fills the height (`calc(100vh - topbar)`). The Learn rail keeps its width; the canvas re-fits when it resizes, using the demo's `Fitter` with a `ResizeObserver`.
- **Entry points** (new store action `openMap(focus?: MapFocus)`, where `MapFocus = {direction?, node?, edge?}`):
  - Gateways step: "Show on map" on each gateway card focuses that gateway and sets the direction from its type.
  - Inventory step: "Show on map" on each engine row and destination row.
  - Audit step: "Show on map" on each grant row focuses that line. Findings that have a resource focus that node.
  - Review step and cart: "Show on map" on grant, revoke and bind items highlights the pending line.
- Step badge: the number of pending lines on the map when the cart is non-empty, otherwise nothing.
- Lazy loading: `const MapStep = lazy(() => import("./map/MapStep"))`, so React Flow and the map code are a separate chunk and the first load is unchanged.

## 3. Library choice

| Option | Size (gzip, approx.) | Pan/zoom/drag | Keyboard / a11y | Fit with the demo look | Effort |
|---|---|---|---|---|---|
| **`@xyflow/react` 12** (what the demo uses) | about 50–60 kB including its CSS; measure with `vite build` | built in (d3-zoom, d3-drag) | focusable nodes and lines, Enter/Space to select, arrow keys move the selected node, ARIA labels | port `nodes.tsx`, `edges.tsx`, edge CSS and `useAnimatedPositions` almost as-is | low |
| Hand-written SVG with our own pan/zoom/drag | about 0 kB, but 600–900 lines of our own code | we write and test it: wheel, pinch, touch, inertia | all ours | the visuals can be copied, the interaction can't | high |
| Cytoscape.js | about 110 kB+ | yes | weak (canvas-rendered) | doesn't match the HTML/CSS node look | medium |

**Pick: `@xyflow/react` ^12**, the same version range as the demo. It's the only new runtime dependency. Lazy loading keeps the main bundle as it is. `vite.config.ts` already has `chunkSizeWarningLimit: 800`. Import `@xyflow/react/dist/style.css` only inside the map chunk. Set `colorMode="system"` and override the `--xy-*` variables as the demo does.

## 4. Data model: building the graph from existing responses

### 4.1 Backend

**v1 needs no backend changes.** Everything comes from `/inventory`, `/gateways`, `/model-armor`, `/context` and `/audit`, which are already loaded by `sync()` in `store.tsx`. The allow/deny logic is a TypeScript port of `backend/policy_studio/dryrun.py`:
- `member_matches`: exact principal, `allUsers` / `allAuthenticatedUsers`, the project's agents principalSet matched against an Agent Identity principal (same trust domain and project number), and `group:` / `domain:` give "unknown".
- `condition_allows`: the read-only-hint form, the `toolName in [...]` form, and anything else gives "unknown".
- The registry-wide key is `projects/<GP>/locations/<R>`.

Optional backend additions, not needed for v1:
1. `GET /api/studio/engine-access`: read-only IAM on each engine (who can query it), so the ingress view can show real callers (see 6.3). Needs checking whether Agent Runtime engines expose `getIamPolicy`; otherwise read project-level `roles/aiplatform.user`.
2. Nothing else. A server-side `/graph` endpoint isn't justified: the inputs are already on the client, and building the graph client-side lets the staged-change view (section 8) run without a round trip.

### 4.2 Frontend type gaps (fix first)

`api/types.ts` is behind API.md. Add:
- `Inventory.access_errors`, `project_agents_principal`, `errors`, `synced_at`.
- `Template.summary`.
- `"registry"` as a destination kind on `Intent.destination.kind`.

### 4.3 Graph types (`frontend/src/map/graph.ts`, pure, no React)

```ts
type Direction = "egress" | "ingress";
type PNodeKind =
  | "engine"            // an Agent Runtime agent as a caller (id = engine name)
  | "principal_group"   // pseudo callers: project agents principalSet, public (allUsers / allAuthenticatedUsers), other principals
  | "gateway"           // id = gateway full name
  | "no_gateway"        // the "no gateway" lane (direct traffic)
  | "anywhere"          // sink for direct egress
  | "client"            // ingress pseudo callers
  | "a2a" | "runtime_dest" | "mcp" | "endpoint" | "endpoint_group" | "registry";
type Verdict =
  | "allowed"      // an unconditional matching grant
  | "partial"      // MCP tools grant: some tools allowed (tool breakdown attached)
  | "conditional"  // condition can't be evaluated client-side (custom CEL, group member)
  | "blocked"      // default deny under ENFORCE (implicit)
  | "would_deny"   // default deny under DRY_RUN: passes today, logged as allowed
  | "dormant"      // grant exists but the caller isn't behind an egress gateway: never checked
  | "direct"       // no gateway: traffic goes straight out
  | "screened" | "unscreened";  // ingress only
type Via = "member" | "project_agents" | "public" | "registry_wide" | "other";
interface Reason {                    // one binding that contributes to a line
  binding: Binding; resource: string; resourceKind: "agent" | "mcp_server" | "endpoint" | "registry";
  resourceLabel: string; via: Via; access: Intent["access"];   // from accessFromCondition()
}
interface PEdge {
  id: string; source: string; target: string; direction: Direction;
  verdict: Verdict; reasons: Reason[];
  tools?: { allowed: string[]; denied: string[]; unknown: string[] };   // MCP only
  gateway?: string; mode?: "ENFORCE" | "DRY_RUN" | null; modelArmor?: boolean;
  implicit?: boolean;             // drawn for default deny, no binding
  inherited?: boolean;            // via a principalSet, public or registry-wide grant (selected agent only)
  pending?: "add" | "remove" | "change"; after?: Verdict; intents?: string[];  // cart view (section 8)
}
interface PolicyGraph { nodes: PNode[]; edges: PEdge[]; stats: {...}; notes: string[] }
buildPolicyGraph(input: {inventory, gateways, modelArmor, context, direction}): PolicyGraph
```

Node ids are full resource names (stable across Sync) or fixed pseudo ids: `pseudo:project_agents`, `pseudo:public`, `pseudo:other`, `pseudo:anywhere`, `nogw:egress`, `nogw:ingress`, `client:any`, `client:ge`. This matters for saved positions (section 7).

### 4.4 Egress rules (agent, destination)

For each engine E and destination D in the inventory:
1. **Gateway:** `E.gateways.egress`, cross-checked against `Gateway.bound_engines` (a mismatch adds a note). Mode = that gateway's `enforcement.mode`.
2. **Bindings:** `access[D] ∪ access[registryKey]`, role `roles/iap.egressor`, where `memberMatches(b.member, E.principal) !== false`.
3. **Verdict:**
   - E has no egress gateway: `dormant` for any grant. E's traffic is drawn as one `direct` line from E to `no_gateway` to `anywhere`.
   - Any unconditional match gives `allowed`.
   - Otherwise MCP: evaluate each tool. All allowed gives `allowed`; some give `partial` (with the tool breakdown); a condition that can't be evaluated gives `conditional`.
   - Non-MCP with a tools or read-only condition: `allowed`, with a note. These calls carry `toolName ''`, which the condition allows; render already warns about this.
   - No match: implicit `blocked` (ENFORCE), `would_deny` (DRY_RUN), or unknown when the gateway has no IAP policy or `enforcement.mode` is null. Implicit lines are only drawn on request (section 5.2).
4. **Who the line is drawn from:**
   - A binding whose member is E's principal: drawn from E.
   - A principalSet binding: drawn once from `pseudo:project_agents`.
   - `allUsers` / `allAuthenticatedUsers`: from `pseudo:public`, flagged red, linking to the matching Audit finding.
   - Service accounts, users, groups, deleted agents: from `pseudo:other`. Deleted agents (a reasoningEngines principal not in the inventory) get a red "deleted agent" chip.
   - Registry-wide bindings: drawn once to the `registry` node ("Agent Registry: all entries").
   - Group and pseudo grants are added to each engine's lines only when that engine is selected (`inherited: true`). Otherwise the engine node shows a count, e.g. "+3 via project-wide grant".
5. **Unreadable IAM:** `access_errors[D]` gives a hatched D node with "IAP policy couldn't be read". No lines to it are guessed.

### 4.5 Routing

The direction is always left to right: callers, then gateway, then destinations, like the demo. Each engine has one trunk segment to its gateway, as in the demo's `seg:orch-egress`. ~~Outside the selected-agent view, gateway-to-destination lines are **combined per destination**: one line, verdict = the best of its contributors, with a count badge ("3 agents"). Selecting an agent replaces this with that agent's own lines, including tool rows and inherited and implicit lines. This keeps the count in the hundreds and readable.~~ **Superseded 2026-10-12** ([§5.4](#54-redesign-2026-10-12-lines-only-for-selected-agents-the-object-picker)): combined lines and their "N agents" badges are gone. Every line belongs to one agent and only the selected agents' lines are drawn; with none selected the map is nodes only.

## 5. Filters and interaction

### 5.1 Toolbar (above the canvas)
- **Direction:** a segmented control, `Agent-to-Anywhere` (default) | `Client-to-Agent`.
- **Gateway affiliation:**
  - `All agents`.
  - `Behind a gateway`: shows allowed connections to remote destinations.
  - `No gateway`: these agents have no policy at all; traffic goes straight out. Each node offers "Stage: bind to <egress gateway>" (a `bind_gateway` intent, as in GatewaysStep). It is disabled when `bindable` is false, with the `Redeploy` help.
- **Gateway** dropdown (only when there's more than one gateway in that direction).
- ~~**Destination types:** A2A, Agent Runtime, MCP, APIs (the same categories as `DEST_TYPES` in BuilderStep), plus "Hide destinations with no grants" (default on; groups them into an `endpoint_group` node "+22 API endpoints with no grants", which expands on click).~~ **Superseded 2026-10-12:** the type checkboxes are gone; the object picker's group checkboxes replace them (§5.4). **Restored later on 2026-10-12** (A2A agents, Agent Runtime, MCP servers, APIs), mirroring the picker's groups of those types (§5.4). "Hide destinations with no grants" (default on; an `endpoint_group` node "+N API endpoints with no grants", which expands on click) is one of the picker's quick toggles; "no grants" now means no grant from any shown caller, whatever is selected. Google API endpoints shown one by one ("Show Google API endpoints") are never grouped as "no grants": the toggle asked for them.
- **Show Google API endpoints** (default off). Endpoints whose URL host is `*.googleapis.com` (any port) are often a platform allowlist, each API registered as host, host.mtls and host:443 and granted project-wide; one by one they crowd out the real destinations. Off, they're one `google_apis` node, "Google APIs (N)", in the API endpoints section, and lines into them are merged per source and kind (granted, default deny) with the best verdict and a count ("16 APIs"); the selected-agent view gets one inherited line and one default-deny line into it. The checkbox is the group's only state: clicking the group, or a search or "Show on map" match inside it, ticks it; unticking collapses it. A selected Google API endpoint stays on its own. Other endpoints are never grouped this way (`view.ts`, `labels.ts`).
- **Endpoint labels** (`labels.ts`): the card title is the host (plus the port when the URL spells one out, since host and host:443 are separate entries) when the display name is empty, equals the host or ends with it ("acme-prod cloudtrace.googleapis.com" → "cloudtrace.googleapis.com"), else the display name. Long hosts are shortened from the middle, eliding the shared domain first (`iamcredentials.mtls…apis.com:443`), in a mono title on a wider card. The full display name and URL are on hover and in the details panel; the table view uses the same labels, in full, with a "Google API" tag.
- ~~**Search:** matches node labels and ids (endpoints also their display name and URL), centers on and briefly highlights the matching node, expanding the Google APIs group and then the "no grants" group when they hide it.~~ **Superseded 2026-10-12:** the object picker's text filter (§5.4) keeps this: it matches name, id and URL, and Enter on a single match does "Only this" and Apply, expanding the Google APIs group and then the "no grants" group when they hide it.
- **Show:** `Today` | `With staged changes` (default when the cart isn't empty) | `Changes only`.
- **Toggles:** "Inherited grants" (project-wide / public / registry-wide on the selected agent), ~~"Implicit denies"~~ (superseded 2026-10-12 by Show: Allows / Denies, §5.4).
- The **legend** doubles as a verdict filter (click to hide or show `allowed`, `partial`, `would_deny`, and so on).
- Buttons: Fit, ~~Reset layout~~ Reset view (2026-10-12, §5.4), Table view.

### 5.2 Showing "block" under default deny
- **Implicit blocked lines are never drawn for everyone.** With N agents and M destinations that's N×M lines, and it says nothing beyond "default deny".
- **Selected agent:** with Show: Denies on (2026-10-12; was "Implicit denies"), thin red dashed lines with an ✕ badge go from that agent to each visible destination it can't reach. They're capped at 60 per agent, then "+N more". With no agent selected, each gateway-backed engine shows "2 allowed" and "denied by default: 18".
- **Dry run:** the same lines use the `would_deny` style (amber dashed line with a red ✕ outline, labelled "Would be denied: passes today (dry run)"). The gateway node gets an amber "Dry run: nothing is blocked" chip. Partial grants in dry run show the denied tools as "would deny".
- **Model Armor:** a shield on the gateway node (with the template id and a hover summary from `Template.summary`). Every line through that gateway gets a small shield marker at the gateway end. Model Armor doesn't change allow or deny; it screens content. If the CONTENT_AUTHZ policy is `DRY_RUN`, the shield is outlined ("screening, not blocking").
- **Conditional grants:**
  - `partial`: green line with a half-filled arrowhead and a "read-only" or "3/6 tools" label. On MCP nodes (with an agent selected) tool rows are colored allowed / denied / unknown, using the demo's `tool-row st-*` style.
  - `conditional`: green dotted line with a "?" badge ("custom condition, not evaluated here").
- **Project-wide principalSet:** one line from "All agents in this project". It's inherited on the selected agent, with an amber note: "applies to agents created later too".
- **Registry-wide:** one line to the "Agent Registry: all entries" node. It's inherited on the selected agent, to every destination.
- **No gateway:** grants held by an unbound agent are `dormant` (gray dotted, "not enforced: no gateway").

### 5.3 Clicks
- **Click a node:** selects it. For an engine or pseudo caller, this ~~switches to the selected-agent view; double-click or "Clear" leaves it~~ toggles its selection (2026-10-12: its lines are drawn or hidden, and several agents can be selected); "Clear" or Esc deselects them all. The side panel shows node details: identity type, gateways, bindable, counts, and actions (bind or unbind, "Build a policy for this agent", which calls `openBuilder` with the source).
- **Click a line:** the policy detail panel (section 9).
- **Drag nodes, pan, wheel or pinch zoom:** with `minZoom 0.2`, `maxZoom 2`, `zoomOnDoubleClick` off (as in the demo). (Implemented with `minZoom 0.08`, so Fit shows the whole us-west1 scale map.)

### 5.4 Redesign (2026-10-12): lines only for selected agents, the object picker

Decided 2026-10-12; supersedes the combined lines (§4.5), the destination-type checkboxes, search and "Implicit denies" (§5.1), and "Reset layout" (§7).
- **Lines only for selected agents.** With no agent selected the map shows nodes only, both directions, with a hint ("Select an agent (click it, or use the picker) to see what it can reach."). Agents keep their summary chips ("2 allowed · Denied by default: 11"). When exactly one agent is in view it's selected automatically (once per set of agents in view, so deselecting it sticks).
- **Per agent, never combined.** `graph.ts` builds every caller's own lines (`caller` on every line): its trunk (or its direct lane and its own No gateway → Anywhere line), then one line per destination with its own verdict (allowed, partial, conditional, inherited, blocked or would_deny, dormant) and the pseudo callers' lines. `view.ts` draws the selected callers' lines only. With several agents selected, each agent's lines are moved a few px apart at the shared ends, labels and tooltips name the agent, badges are staggered, and hovering an agent (or its line) dims the others' lines.
- **Show: Allows / Denies** (Agent-to-Anywhere, while an agent is selected): Allows = allowed, partial, conditional, inherited and not-enforced grants; Denies = the default-deny lines (blocked, would_deny, unchecked). Lanes always show. Default-deny lines are capped at 60 per agent ("+N more"). Client-to-Agent has no denies, so no control.
- **The object picker** ("Objects: 3 of 42") replaces search and the type checkboxes: text filter (name, id, URL), Select all / Clear, groups by type with counts and a group checkbox, multi-select checkboxes, "Only this" on hover or focus, quick toggles (Hide destinations with no grants, Show Google API endpoints), Cancel / Apply on a draft. Checked = on the map. Checking an agent row also selects it; group checkboxes, Select all and the affiliation shortcut only show or hide. A checked agent's row has a "Lines" toggle (select or deselect without hiding). Clicking an agent on the canvas toggles its selection. A hidden destination (or gateway) that a selected agent has a line to is drawn faded, "(hidden by filter)". All agents / Behind a gateway / No gateway pre-set the agents' (and gateways') checks; the button lights when the checks match one. Saved per project, region and direction (`studio.map.picker.v1:…`, next to the pins).
- **The picker reflects the map (2026-10-12, after user feedback "updating the map filters should update the list entries").** One source of truth: a row's checkbox isn't stored, it's read off the view (`pickerStatus`): checked = on the map as itself; unchecked = not, with a muted reason ("hidden: no grants", "hidden: Google API (collapsed)", "hidden: type filter", "hidden: no gateway" / "behind a gateway" / "No gateway filter" (the affiliation shortcut), "hidden: other gateway", "hidden: not changed" (Changes only)). A faded node (unchecked, drawn for a selected agent's line) stays unchecked, noted "drawn faded". Group checkboxes and "Objects: N of M" count the same statuses. The state holds only choices: `off` (unchecked by hand), `forced` (checked by hand although a filter hides it: a **manual override**, marked in the row), `typesOff`, the selection and the quick toggles; the filters (toolbar, quick toggles, groups expanded on the canvas, Changes only) hide what they hide, so changing one unchecks its rows and relaxing it checks them again. Changing a quick toggle or the gateway filter (or Show) drops that filter's overrides: the newer choice wins. The quick toggles stay part of the draft until Apply; the rows show the draft at once. A click outside with changes pending no longer drops them (it keeps the popover open: "Apply or Cancel your changes"), and a click on the canvas never closes it: a canvas selection, auto-select or Show on map while it's open is merged into the draft (`rebaseDraft`), keeping the rows changed there. Client-to-Agent lists only what it can show (agents, gateways, clients); type filters don't apply there. Saved as before (`studio.map.picker.v1:…`): the first v1 shape loads with no overrides and no type filters.
- **Type checkboxes restored (2026-10-12):** A2A agents, Agent Runtime, MCP servers and APIs (= the API endpoints and Google APIs groups) are back in the toolbar (Agent-to-Anywhere). Each box mirrors the picker's group of that type: both read the same rows (checked, partly checked, unchecked) and both call the same toggle, so they can't disagree. Unchecking hides the type ("hidden: type filter"); checking restores it as it was (rows unchecked by hand checked again) or, if other filters still hide all of it, shows it anyway. A box is partly checked (or unchecked) when other filters hide some (or all) of its objects, e.g. "Agent Runtime" registry entries with no grants; the tooltip says so.
- **Reset view** collapses the expanded groups, clears pins, resets the picker (everything visible, nothing selected, then auto-select), and fits the layout's bounds. Direction, Allows / Denies and Inherited grants stay.
- **Table view** lists the selected agents' lines; with none selected, every shown agent's own grants (and the pseudo callers'), so it stays a full alternative for screen readers.
- **Changes only** with nothing selected draws the lines of every agent the cart changes.
- **Fixed with it:** the custom node type for "+N … with no grants" was named `group`, one of React Flow's built-in types, so its wrapper got React Flow's group-node styles (150px wide, 10px padding, a dark 1px border, a translucent fill, and a selection shadow): a stray rectangle behind the card. It's `nogrants` now, every node wrapper is reset (no padding, border, fill or shadow), and focus and selection are a ring on the card itself.

## 6. Direction-specific views

### 6.1 Agent-to-Anywhere (default)
Columns: **callers** (engines grouped by egress gateway, then the "no gateway" group, then pseudo callers) → **gateways** (egress gateways stacked, plus a faded "No gateway" placeholder like the demo's detached gateway) → **destinations** (sections: Agent Registry (all entries), A2A agents, Agent Runtime agents, MCP servers, API endpoints) → an `Anywhere` sink to the right, used only by direct traffic.

Agent Runtime agents appear twice by design: as a caller (an engine) and as a destination (a `runtime_dest` registry entry). They're linked by a "same agent" icon, and clicking it moves the selection to the other one. Merging them would create lines inside one column and break the left-to-right reading.

### 6.2 Client-to-Agent
Columns: **clients** → **ingress gateways** (and "No ingress gateway") → **agents** (engines bound for ingress first, then unbound ones).

### 6.3 Showing allowed client connections honestly
A CLIENT_TO_AGENT gateway **doesn't check caller identity**. It screens content with Model Armor. Who may call an agent is decided by Agent Runtime IAM, which Policy Studio doesn't read today. So:
- Client nodes are:
  - `client:any`: "Any caller allowed by the agent's Agent Runtime IAM (not read by Policy Studio)".
  - `client:ge`: shown when `ctx.ge_app` is set. "Gemini Enterprise app <ge_app> (from Context; registration not verified)".
- Lines have no identity verdict:
  - `screened`: through a gateway with Model Armor on (orange shield, template summary).
  - `unscreened`: through a gateway with Model Armor off (neutral, "In the path, no screening").
  - `direct`: the agent isn't bound for ingress.
- If an ingress gateway has an IAP REQUEST_AUTHZ policy (possible with a shared extension), show it as a chip exactly as configured, with the tooltip "Configured; Client-to-Agent doesn't check caller identity" (see open question 3).
- Clicking an ingress line shows the gateway, the Model Armor template filters, and actions: `model_armor_on` / `model_armor_off`, `unbind_gateway`, and "Set up Model Armor" (`openMaSetup`). There's no "allow policy" to show, and the panel says so.
- Optional backend item 4.1(1) would replace `client:any` with real principals.

## 7. Layout, scale and saved positions

**Auto layout:** fixed columns by type, as in the demo's `build.ts` (`GAP_X 110`, column widths from node kind), with no dagre or elk. The graph is at most four columns and nearly two-sided, so a general layered layout adds size without much gain (elk is about 1.4 MB; dagre about 30 kB gzipped). Within each column:
1. Group by section (gateway affiliation, or destination kind).
2. Order with **one or two barycenter passes**: destinations sorted by the average y of the callers allowed to reach them, then callers re-sorted by the average y of their destinations. This is deterministic, with ties broken by label.
3. A destination section with more than 25 items wraps into sub-columns. (Implemented: callers wrap too, at 10 per sub-column, once there are more than 25 of them; engine nodes are tall, so 50 agents in one column were twice the height of the destinations.)
4. Without a selected agent, MCP nodes are compact (a "6 tools" chip). They expand to tool rows when selected or when an agent is selected; node height comes from a `nodeHeight()` like the demo's.

**Scale target:** 50 engines, 100 destinations, 500 bindings, below 16 ms per pan frame on a laptop.
- ~~Combined lines plus the selected-agent view (section 4.5).~~ Superseded 2026-10-12: lines only for the selected agents (§5.4); the layout orders nodes by every shown caller's own grants, so selecting doesn't move them.
- `onlyRenderVisibleElements`, memoized node and line components (as in the demo), and `buildPolicyGraph` inside `useMemo` keyed on the data objects and the cart.
- Particles (`animateMotion`) only on lines in the current selection, and none under `prefers-reduced-motion`.
- Too many lines: when the drawn lines exceed 400, a banner suggests selecting fewer agents (or unticking Denies).

**Saved positions: yes, localStorage, only for nodes you drag.**
- Key: `studio.map.v1:<project>:<region>:<direction>` → `{[nodeId]: {x, y}}`, written with `save()` from `lib/util.ts` and debounced on `onNodeDragStop`.
- Auto layout places every node that hasn't been pinned. Pinned nodes keep their place across Sync and filter changes. Ids no longer in the graph are dropped on load. A `v1` layout-version bump clears everything.
- "Reset view" (was "Reset layout") clears the key. A pinned node shows a pin icon; "Unpin" sends that one node back to auto layout.
- Zoom and pan aren't saved: it fits on open and on direction or filter change, using the demo's `Fitter` (it re-fits after layout animation and on resize).
- Moves between lanes (bind or unbind staged) glide, using the demo's `useAnimatedPositions`.

## 8. Staged cart changes on the map

Build the graph **twice**: `before = build(state)` and `after = build(simulate(state, cart))`. The new pure module `map/simulate.ts` applies intents to cloned Inventory and Gateways:
- grant / revoke add or remove bindings, matching on the **condition expression**, as the backend's `remove_binding` / `same_condition` does.
- bind / unbind set `engines.gateways` and `bound_engines`.
- set_enforcement sets `enforcement.mode`.
- model_armor_on / off set `enabled`.

Comparing the two graphs by line id gives:
- **pending add:** yellow dashed, animated, with a clock badge (the demo's `st-pending`), labelled with the after-verdict ("will allow read-only tools").
- **pending remove:** the original line style with a red dashed overlay and a clock; the after-verdict is "blocked by default", or "would be denied" in dry run.
- **pending change:** the line in its after-style plus a clock, with "Today: full access → After: read-only tools".
- Lanes: a staged bind or unbind moves the engine between lanes (animated) with a "binding staged" chip. A staged set_enforcement shows on the gateway chip as "Dry run → Enforce (staged)", and would-deny lines become blocked in the after-view. Model Armor on or off shows a pending shield.

Each pending item in the panel lists its cart intents with "Remove from cart" (`removeIntent`), "Edit in builder" (`openBuilder(intent, {editId})`), and "Review" (`openReview(id)`). The overlay is a preview; Review's `/diff` and `/preflight` stay the authority, and the panel links to them. `mock.ts` already applies intents to its in-memory world; `simulate.ts` can later replace that logic once it matches on expressions (see section 12).

## 9. Policy detail panel and actions

A right-hand overlay panel inside the canvas (glass style, `components/Glass.tsx`; the same pattern as the demo's `SidePanel`). It closes on Esc and returns focus to the line.

**For an allowed, partial or conditional line, one card per `Reason`:**
- A sentence: `Binding.english` from the backend (for example "Helpdesk Agent can call only the read-only tools of Tickets MCP.").
- **Binding:** role `roles/iap.egressor`; member (label plus the full string, monospace, copyable); **resource** (label, kind icon, full name; "Registry-wide: every entry" when it applies); **via**: direct, all agents in project, public, or registry-wide.
- **Condition:** title, the plain-English line, and the CEL in a collapsible `CodeView`. MCP lines add a tool table with ✓/✕/? per tool and read-only or destructive badges.
- **Context:** gateway, mode (with a dry-run warning), Model Armor template, shared-extension note.

**Actions (they only stage; nothing is written directly):**
- **Revoke:** `addIntents([grantToRevoke(g)])`. The revoke carries the binding's exact condition: `access = {...accessFromCondition(expr), title: condition.title}`, or no access when unconditional. Revoke is destructive, so Apply already asks for `acknowledge_destructive`.
- **Change access (decision 2026-10-12: one `modify` intent):** an inline **AccessChooser** with all / read-only hint / specific tools (tool checklist) / custom CEL (with `lintExpression`). It stages **one** intent, `kind: "modify"`, which carries `access_from` (the existing binding's exact condition, as revokes do since 7e4c1d8) and `access` (the new one). Only enabled when the access differs from the current one.
  - Why not a grant alone: IAM adds bindings rather than replacing them, so a grant would leave the old access in place.
  - Why not a revoke + grant pair: one cart line can't be half-removed, and it applies as **one** read-modify-write with no in-between state.
- **Open in builder:** `openBuilder(grantToIntent(g, ..., "grant"), {mode: "grant"})`, for changing the caller or destination.
- **Inherited grants** (project-wide, public): the revoke and change buttons act on the *group* binding, with a warning: "Removes access for all 7 agents in this project." There's also an option "Limit to this agent instead", which stages a grant for this engine plus a revoke of the group binding.
- **Implicit blocked or would-deny lines:** "Allow…" opens the AccessChooser (default: read-only hint for MCP, full access otherwise) and stages a `grant`; or "Open in builder" with source and destination pre-filled.
- **No-gateway agent:** "Bind to <egress>" (`bind_gateway`).
- **Dry-run gateway:** "Enforce" stages `set_enforcement`, reusing GatewaysStep's shared or dedicated choice. Simplest is a link to the gateway card on the Gateways step.

**Reusing the builder:** pull the "How much access" section out of `steps/BuilderStep.tsx` (the `Choice` radios, tool checklist, custom CEL with lint, `effMode` rules) into `components/AccessChooser.tsx` with `{destination, value, onChange}`. Use it in both the builder and the panel. The builder's `useChecks` warnings (destructive tools, an existing broader grant, project-wide) are pulled out too (`lib/checks.ts`) so the panel shows the same warnings. The panel shows the live `/render` sentence for the staged intent (debounced, as in the builder).

Footer on the panel: "Nothing changes until you Review and Apply", with the cart count and a "Review" button.

### 9.1 The `modify` intent (backend)

A new intent kind used by the map's "Change access" and the builder:

```
Intent{kind: "modify", source, destination,
       access_from: {mode: "custom", expression, title} | {mode: "all"}   // the existing binding, exact
       access:      Access}                                               // the new one
```

- **Apply** (`apply.py`): one getIamPolicy, then remove the binding matching `access_from` exactly (`same_condition`), then add the new binding, then one setIamPolicy with the etag (version 3, other bindings untouched), then read back. On an etag conflict, retry once from a fresh read.
  - **Preflight blocks** it when `access_from` isn't found ("The grant changed since you looked; Sync and try again") or when `access` equals `access_from`.
  - **Undo** is the reverse `modify`.
  - It isn't destructive in the acknowledge sense when the new access is narrower or equal. When it removes all access (not possible: use revoke) or broadens it, show a warning.
- **Diff:** status `replace`, with `current` and `after` bindings and a detail like "full access → read-only tools".
- **Render:** gcloud, REST, Python and Terraform must each make the change in one step.
  - gcloud: one `get-iam-policy`, then edit the YAML or JSON to change the condition in place, then one `set-iam-policy`. Avoid `remove-iam-policy-binding` + `add-iam-policy-binding`.
  - REST and Python: getIamPolicy, then the replace, then setIamPolicy with the etag.
  - Terraform: `google_iap_..._iam_member` keyed by condition is a destroy + create. Say so in the comment, and suggest `create_before_destroy`, or the `_iam_policy` resource if the user manages the whole policy.
- **English:** "Change Helpdesk Agent's access to Tickets MCP: full access → only read-only tools."
- **Mock:** `mock.ts` applies, diffs and undoes `modify`. `mockRender` renders it.
- **Files:** `model.py` (kind + `access_from`), `apply.py`, `preflight.py`, `diff.py`, `render.py`, `english.py`, `api.py` validation, `docs/API.md`; frontend `api/types.ts`, `lib/policy.ts`, `lib/apply.ts` (destructive/warn rules), `panels/Cart.tsx` (label), and both mock files.
- **Tests:** a round trip for every pair among unconditional, read-only hint, tools and custom. The other bindings of the same role must stay untouched. Also: etag retry, "not found" blocked, undo, render outputs (including terraform validate on the bundle), and the mock matching the backend.

## 10. Accessibility, keyboard, themes

- **Table view** (toolbar toggle, also the screen-reader alternative): a sortable table of the visible lines (caller, gateway, destination, verdict, via, condition, pending), with the same row actions. It's built from the same `PolicyGraph`, which also makes it the simplest thing to test.
- React Flow: `nodesFocusable` and `edgesFocusable`; Tab moves through nodes and lines, Enter or Space selects (opening the panel), arrow keys move a selected node (and save its position), Esc clears the selection. Set `ariaLabelConfig`, an `aria-label` on each node ("Helpdesk Agent, Agent Runtime, behind corp-egress, 5 allowed destinations") and each line ("Helpdesk Agent to Tickets MCP: read-only tools allowed"), and an `aria-live` region announcing filter results and selection.
- **Color is never the only cue:** dash patterns, ✕ / shield / clock / "?" badges, half-filled arrows for partial, and text labels in the legend.
- `prefers-reduced-motion`: no particles, no dash animation, instant moves.
- **Themes:** reuse the existing `--e-*` tokens in `styles.css`, which already have light and dark values (the same names as the demo). Add `--e-partial`, `--e-would-deny`, `--e-dormant`, `--e-screened` in both schemes. All map CSS goes under a `.pmap` prefix. Check contrast of line colors against `--surface-2` in both schemes (WCAG 3:1 for graphics).

## 11. Mock data (`frontend/src/api/mockData.ts`, `mock.ts`)

The current mock world already covers a lot:
- **Gateways and enforcement:** corp-egress, which is dry run in us-east4 on a shared extension and enforcing in us-central1, and corp-ingress.
- **Agents:** a bound helpdesk agent (egress and ingress), an HR agent (egress only), an unbound Travel Planner, and an agent that can't be bound (it uses a service account).
- **Grants:** read-only-hint and tools conditions, project-wide principalSet grants on three endpoints, `allAuthenticatedUsers`, and a deleted-agent grant.
- **Google API platform allowlist** (added with the Google APIs group): 13 `acme-prod <host>` endpoints (plain, .mtls and .mtls:443 forms, plus a regional `aiplatform.<region>.rep` host) with a project-wide grant, and two endpoints that aren't Google APIs (Weather API, granted to Travel Planner; Partner payments, no grants).

Add:
1. A **registry-wide** binding in one region (for example a service account `serviceAccount:ops-bot@my-demo-project.iam.gserviceaccount.com` on `projects/<P>/locations/<R>`).
2. A **custom-CEL** grant and a **`group:`** member grant, giving `conditional` and "unknown".
3. An **`access_errors`** entry for one destination (unreadable IAP policy).
4. A second engine bound for **ingress**, and `Template.summary` lines in the Model Armor mock.
5. A **scale scenario**: region `us-west1` generates about 50 engines, about 15 MCP servers, about 100 endpoints and about 500 bindings from a seeded PRNG, with names like `agent-017`, all under `my-demo-project`. It's used for performance and layout checks. (Implemented in `api/mockScale.ts`, with corp-ingress screened by Model Armor and a second ingress gateway without it. With the default filters it draws about 320 combined lines, under the 400-line banner; `?scale=2` on the page URL doubles it, past the banner.)
6. A **multi-gateway** scenario (two egress gateways) in the scale region.
7. Make the mock's revoke match on **condition expression** (today it matches on title) so the staged-change view and mock Apply agree with the backend.

## 12. Fixes to make first (found while planning)

1. **Done in 7e4c1d8. Revoke of a conditional grant.** `lib/grants.ts` `grantToIntent(g, ..., "revoke")` leaves out `access`. The backend's revoke removes only the binding whose condition **expression** matches (`apply.py remove_binding` with `conditions.same_condition`), and no access means unconditional. So revoking a conditional grant from Audit or the builder's revoke list probably ends in "skipped: Not granted". Fix: always put the binding's condition on the revoke (`accessFromCondition(expr)` plus `title`). Add a backend test that runs a round trip of grant, revoke from the Grant, and verified.
2. **Done in 7e4c1d8. Registry-wide grants:** `grantToIntent` maps `resource_kind "registry"` to `"endpoint"`. Use `"registry"`, as API.md allows (id `""`, name `projects/<P>/locations/<R>`).
3. **Builder copy:** `useChecks` says "Applying this replaces it" for an existing different condition. IAM adds the new binding alongside the old one. Change the message and offer "Change the existing grant instead", which stages the same `modify` intent the map uses (section 9.1).
5. **Step keys:** move navigation from step numbers to step keys (section 2) before inserting the map as step 1.
4. Type gaps (section 4.2).

## 13. Files

New, under `frontend/src/map/`:
- `evaluate.ts`: `memberMatches`, `conditionAllows`, tool evaluation (port of `dryrun.py`).
- `graph.ts`: `buildPolicyGraph` (pure).
- `simulate.ts`: apply cart intents to cloned state (pure).
- `diff.ts`: compare before and after graphs.
- `layout.ts`: columns, barycenter ordering, wrapping, pinned positions.
- `toFlow.ts`: PolicyGraph to React Flow nodes and lines.
- `nodes.tsx`, `edges.tsx`: ported from the demo; engine, gateway, destination, pseudo, group and sink node types; `policy` line type with the verdict styles.
- `MapStep.tsx`: toolbar, canvas, legend, empty and loading states (using `Load` from `components/ui.tsx`).
- `PolicyPanel.tsx`: line and node details and actions.
- `MapTable.tsx`: the table view.
- `usePositions.ts`: localStorage pins.
- `labels.ts`: endpoint labels (host title, middle ellipsis) and Google API detection; tested in `google.test.ts` with the Google APIs group.
- `picker.ts`, `ObjectPicker.tsx` (2026-10-12, §5.4): the object picker's pure logic (rows, each row's status read off the view, filter, groups, type filters, manual overrides, Only this, Apply, rebasing the draft, the affiliation shortcut, auto-select, Reset view, Show on map focus, saved state) and its popover; tested in `picker.test.ts`.

Also new: `components/AccessChooser.tsx` and `lib/checks.ts` (pulled out of BuilderStep).

Changed:
- `App.tsx`: the map as step 1 (lazy), step-key navigation, full-width class, footer text.
- `store.tsx`: `STEPS` entry, `mapFocus`, `openMap`.
- `steps/BuilderStep.tsx`: use AccessChooser and checks.
- `steps/GatewaysStep.tsx`, `InventoryStep.tsx`, `AuditStep.tsx`, `ReviewStep.tsx`, `panels/Cart.tsx`: "Show on map" buttons.
- `lib/grants.ts`: `grantToRevoke` and `grantToModify` (12.1 and 12.2 were fixed in 7e4c1d8).
- Backend for `modify`: see section 9.1.
- `api/types.ts`, `api/mockData.ts`, `api/mock.ts`, `styles.css` (the `.pmap` block).
- `package.json`: add `@xyflow/react`; dev dependency `vitest`.

## 14. Tests

The frontend has no test runner today. Add **vitest** (dev only; it shares the Vite config) with `npm test`.
- **Matching kept in step with the backend:** one fixture, `backend/tests/fixtures/egress_cases.json` (member, principal, condition, tool, read-only map, expected verdict), read by both a new pytest (`test_dryrun_parity.py`, calling `member_matches` / `condition_allows`) and `map/evaluate.test.ts`. Any change on one side then fails the other's test.
- **Graph:** `buildPolicyGraph` over `buildWorld({project: "my-demo-project", region: "us-east4"})`. Check line verdicts for each case in section 4.4 (direct, project-wide, public, registry-wide, partial tools, custom, unbound/dormant, unbindable, dry run would-deny, access_errors). Also us-central1 (ENFORCE) and us-west1 (scale: line counts with and without combining, build time under 50 ms).
- **Staged changes:** grant, revoke (expression match), modify pair, bind, unbind, set_enforcement, Model Armor on/off give the expected pending add, remove or change.
- **Intents:** `grantToRevoke` carries the exact expression; `grantToModify` gives one `modify` intent with `access_from` = the exact current condition; registry-wide gives `destination.kind "registry"`; adding the same thing twice is deduplicated by `addIntents`.
- **Layout:** deterministic for the same input; pinned nodes stay put; unknown pins are dropped; barycenter doesn't increase crossings on fixtures.
- **Backend:** the revoke round trip (12.1), against `fakegcp.py`.
- **Manual QA** in mock mode: both themes, keyboard-only use, reduced motion, 200% zoom, the us-west1 scale region. Optional: a Playwright smoke test (open question 9).

## 15. Phases (rough sizes)

| Phase | Content | Size |
|---|---|---|
| 0 | Step-key navigation and the map as step 1 (shell only); fixes 12.3–12.4; vitest; `evaluate.ts` plus the shared fixture | S–M (1.5 d) |
| 0b | Backend `modify` intent (section 9.1): apply, preflight, diff, render (4 formats), English, undo, mock, tests | M (1.5–2 d) |
| 1 | `graph.ts`, `layout.ts`, `toFlow.ts`, ported nodes and lines, MapStep (step 1, lazy, full width), egress read-only, legend, light and dark | M (3 d) |
| 2 | Filters (direction, affiliation, gateway, type, search), selected-agent view, combined lines, inherited and implicit lines, dry-run and Model Armor styles, table view | M (2–3 d) |
| 3 | Policy panel; AccessChooser and checks pulled out of the builder; revoke, change access, allow, bind actions; the staged-change view | M (3 d) |
| 4 | Dragging, saved positions, reset and unpin, keyboard and ARIA, reduced motion, "Show on map" links from the other steps | S (1–2 d) |
| 5 | Client-to-Agent view (section 6.3) and its actions | S (1 d) |
| 6 | Mock scenarios (section 11), performance tuning at scale, docs (README and API.md notes) | S–M (1–2 d) |
| 7 (optional) | Observed traffic: overlay `/gateway-logs` (allowed, denied, computed would_deny from the last 24 h) on the lines. Uses the existing endpoint, no backend change | M (2 d) |
| 8 (optional) | Backend `engine-access` for real ingress callers | M (2 d) |

Total for v1 (phases 0–6): about 13–17 days.

## 16. Open questions

1. ~~Placement~~: **decided 2026-10-12: step 1, right after Context** (section 2).
2. Should saved positions be per project, region and direction (proposed), or shared across directions? Should zoom and pan be saved too?
3. Ingress IAP: when an ingress gateway has an IAP REQUEST_AUTHZ policy, does CLIENT_TO_AGENT ever enforce it? The plan shows it as configured, not as identity enforcement.
4. Is the optional backend `engine-access` (Agent Runtime IAM) wanted, so the ingress view can name real callers?
5. ~~Change access~~: **decided 2026-10-12: a single `modify` intent** (section 9.1).
6. Inherited grants: should "Limit to this agent instead" be offered by default, or is that too much of a change to suggest?
7. Implicit-deny cap: are 60 lines per selected agent and summary counts elsewhere right for your largest project?
8. Grants above the registry (project, folder, organization) aren't read, as in `dryrun.py`. Is a note on the map enough?
9. Tests: is adding vitest (and optionally Playwright) to the frontend acceptable?
10. Should the observed-traffic overlay (phase 7) be part of v1, given it reuses `/gateway-logs` with no backend work?
