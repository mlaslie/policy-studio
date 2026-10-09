> Original design plan, written inside the [Agent Gateway & Agent Registry demo](https://github.com/mlaslie/agent-gateway-demo) repo. Paths like `agdemo_core/…` refer to that repo; Policy Studio itself is standalone.

# Policy Studio: plan

**Status: planned.** Decisions are recorded at the end. Build order: P1 → P4.

## Why

Turning on Agent Gateway, Model Armor and the IAM policies behind them is hard for most people. It involves many resources: gateways, authz extensions and policies, Model Armor templates, Agent Registry entries, Agent Identity principals, and IAP grants with conditions. Each one has its own API and its own gcloud quirks, and the result is hard to read afterwards.

Policy Studio is a guided mode in the UI that does three things:
1. **Teach.** Show how each policy is built and what the generated IAM actually means.
2. **Craft and apply.** Pick the agent, pick the destination, choose how much access, then copy the commands or apply them.
3. **Audit and update.** See what's in place in a project and region, explain it in plain English, and change or revoke it.

The demo tabs (scenarios 1–7) stay as they are: they tell the story. The Studio is the "now do it yourself" tool.

## Where it lives

A new top-level switch in the header: **Demo | Policy Studio**. The Studio has its own layout:
- **Left:** a stepper (the steps below).
- **Center:** the current step.
- **Right:** the **policy cart** (staged policies) and a **Learn** panel that explains the current step.

The Studio isn't tied to a theme. It works on whatever project and region you point it at, and the demo project is the default.

## Steps

### 0. Context
- Fields:
  - **project ID** (the project number is looked up automatically)
  - **region**
  - optional **gateway project**, if egress gateways live in another project
  - optional **Gemini Enterprise app ID and location**
- These values fill in every generated command and Terraform variable as you type.
- **Check access:** confirms the APIs are enabled and that your credentials can read, and optionally write, gateways, authz policies, Agent Registry, IAP IAM and Model Armor. It shows a green/amber/red list with the exact missing role and the command to grant it.

### 1. Gateways
- **List:** every Agent Gateway in the region, with:
  - its type (egress `AGENT_TO_ANYWHERE` / ingress `CLIENT_TO_AGENT`)
  - its bound Agent Registry
  - the authz policies attached (IAP, Model Armor)
  - **which Agent Runtime agents are bound to it**, read from each engine's `agentGatewayConfig`
- **Rules shown inline:** "one egress and one ingress gateway per project and region for Runtime agents"; Runtime agents created before 2026-04-29 can't be bound.
- **Create gateway:** a short form (name, type, registry), with the IAP authz extension and policy for egress offered as one bundle. It produces commands and can stage them.
- **Bind or unbind an agent to a gateway:** stage the engine PATCH.

### 2. Model Armor
- For each gateway: is a `CONTENT_AUTHZ` policy attached? If so, the extension, then the **template**, then the template's **filters and confidence levels**:
  - prompt injection / jailbreak
  - sensitive data (basic/advanced)
  - responsible AI categories
  - malicious URLs
  - plus the custom block message.
- Shown as a readable card, e.g. "Prompt injection: HIGH and above", "SSN, credit card: blocked".
- **Turn on or off** per gateway (stage), or **create or edit a template** with toggles for each filter.
- Notes the verified behavior: egress screening covers MCP traffic but not A2A.

### 3. Inventory (Agent Registry)
- **Tabs:**
  - **Agents:** Runtime agents (auto-registered) and A2A agents, with their skills.
  - **MCP servers:** each tool with its READ/WRITE hints.
  - **APIs / endpoints:** each endpoint with its host.
- Each asset shows **who can reach it** (reusing the registry browser) and links to "build a policy for this".
- **Source agents:** Agent Runtime engines in the region, with their Agent Identity principal (the long `principal://…` value, shown and explained).

### 4. Build a policy (the core wizard)
1. **Who (source):**
   - one agent's identity, pick from the list
   - all agents in the project (`principalSet`)
   - or a custom principal
2. **What (destination):** an A2A agent, an MCP server or an API endpoint from the inventory.
3. **How much:**
   - A2A and API: **full access**.
   - MCP:
     - **all tools**
     - **read-only by MCP hint** (`mcp.tool.isReadOnly`), with a "new read-only tools are included automatically" note
     - **specific tools by name**: a checklist of the server's tools with hint badges and "select all read-only"
     - **custom expression** (advanced).
   - Optional, future (#4): **time limit** (until a date/time, or business hours).
4. **Preview:** a plain-English sentence ("HR Assistant can call only the read-only tools of Tickets MCP"), plus an **IAM anatomy card** that labels each part of the generated grant:

   ```
   resource:  …/iap_web/agentRegistry/mcpServers/<id>      ← what is being protected
   role:      roles/iap.egressor                            ← "may send traffic to it through the gateway"
   member:    principal://agents.global.org-…/reasoningEngines/<id>   ← the agent's identity
   condition: api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || …toolName == ''
              └ why the `''` is there: MCP setup calls (initialize, tools/list) carry no tool name
   ```
5. **Add to cart.** You can also edit, duplicate or remove staged items.

Prerequisites are checked as you go:
- is the source agent bound to an egress gateway?
- is the destination registered?
- is there already a grant that makes this one redundant?

Problems show as amber hints, each with a one-click "also stage the fix".

### 5. Review and output (cart)
- Staged items in order: gateway creates, bindings, Model Armor changes, then grants.
- For **one item or the whole cart**, output tabs:
  - **Terraform:** resources and variables, reusing `agdemo_core/terraform.py`
  - **gcloud:** with exact `--condition` quoting
  - **REST (curl):** with `gcloud auth print-access-token`
  - **Python** (optional)

  Each tab has a **Copy** button (per block and "copy all"). **Download** gives `main.tf`/`variables.tf`, or a ready-to-run `apply.sh`.
- Where a tool can't do something, the tab says so and shows the fallback. For example, there's no gcloud command for binding an engine to a gateway, so it shows the curl PATCH (per the #17 research).
- **Diff vs. current state:** for each item, "will add", "already present" or "will replace", with the current IAM policy shown next to the result.

### 6. Apply
- **Apply this item** or **apply all**, only for admins and after a confirmation that names the project and lists every change. Destructive changes require typing the project ID.
- Progress uses the existing pending-timer pop-outs (typical times per operation).
- **Read-back verification** after each item. For example, re-read the IAM policy and confirm the binding exists with the same condition. For agents this UI can call, it can optionally run a live test call.
- **Undo:** each applied item records its inverse, so "revert last apply" works.

### 7. Audit
- **Everything in the region in plain English:** "Helpdesk Agent → KB Agent: full access", "HR Assistant → Tickets MCP: read-only by hint (expires …)", "All agents in project → 25 Google API endpoints".
- Gateways with and without Model Armor, and agents not bound to any gateway (flagged as "unprotected egress").
- **Findings:**
  - grants with no gateway in the path
  - unconditional access to MCP servers that have destructive tools
  - grants to principals whose engine no longer exists
  - `allUsers`-style members
  - …
- **Edit:** loads a grant into the wizard. **Revoke:** stages the removal. **Export:** generates Terraform for the current state.
- **Sync:** re-reads the project and region (all of the above) on demand, with a "last synced" time. It reuses the current Sync button's behavior, with the scope widened to the whole region.

### Learn panel (all steps)
A short, step-specific explanation with a diagram:
- what a gateway does
- why egress is default deny
- what Agent Identity is
- how IAP decides egress
- what the `''` in conditions is for
- how Model Armor attaches.

Each comes with a "Show me in the demo" link to the matching demo tab, plus a glossary.

## Architecture

```
agdemo_core/studio/
  discovery.py   read-only: gateways, authz extensions/policies, Model Armor templates, registry assets,
                 Runtime engines (+ gateway config, principals), IAP IAM per registry resource
  intents.py     PolicyIntent model: kind (create_gateway | bind_gateway | model_armor | grant | revoke | template),
                 source, destination, access {all | read_only_hint | tools[] | custom}, condition, params
  render.py      intent -> {terraform, gcloud, rest, python} (reuses terraform.py, iap conditions, gateways YAML)
  apply.py       intent -> GCP calls via existing agdemo_core.gcp.* (engines.set_gateway_paths, iap, gateways,
                 model_armor), with read-back verification and inverse ops for undo
  audit.py       IAM + gateway + Model Armor state -> intents + findings (plain-English)
ui/backend:     /api/studio/{context, check, gateways, model-armor, inventory, render, diff, apply, audit, sync}
ui/frontend:    StudioMode (stepper, steps, cart, Learn panel, output tabs with copy), reusing Glass/CodeView,
                progress pop-outs, registry cards
```

**Design rules:**
- **Read-only by default.** Every write goes through `apply.py`, is admin-only, needs confirmation and is logged in Activity.
- **Generic.** No assumptions about the `agdemo` prefix or themes, so the Studio works on any project.
- **One source of truth for commands.** The Studio, "Under the hood" and the Terraform export all come from `render.py`, so all three always match.
- **Every generated item is tested:** `terraform validate`; gcloud flag checks against `--help` in CI; the REST shape is tested against the handlers.

## Phases

| Phase | Delivers | Writes to GCP? | Effort |
|---|---|---|---|
| **P1 Discover and audit** | Context and access check, gateways list, Model Armor view, inventory, current policies in plain English, findings, region Sync | No | M |
| **P2 Build and generate** | Policy wizard (all access options), IAM anatomy, cart, Terraform / gcloud / REST (+ Python) with copy and download, diff vs current | No | M |
| **P3 Apply** | Apply item or all, confirmations, progress, read-back, undo, Activity log entries | Yes | M |
| **P4 Create infrastructure** | Create gateway (+ IAP bundle), bind/unbind agents, Model Armor template editor, turn Model Armor on or off per gateway | Yes | M–L |

Each phase ships on its own. P1 and P2 are safe in any project because they don't write anything.

## Decisions (Oct 2026)

| Topic | Decision |
|---|---|
| **Scope** | Any project and region the backend's credentials can reach. The demo project is the default. Nothing assumes the `agdemo` prefix or themes. |
| **Where Apply runs** | The hosted UI (Cloud Run, UI service account) can apply in the **demo project**. For any other project, run the Studio locally (`./agdemo ui local`), which uses your own gcloud credentials. In the hosted UI, other projects get discovery, audit and generated commands, with Apply disabled and a "run locally to apply here" hint. Copy/paste commands work everywhere. |
| **Output formats** | **Terraform, gcloud, REST (curl) and Python.** Python uses the google-cloud client libraries (several are pre-1.0). The engine gateway binding has no clean Python method, so that tab shows the `AuthorizedSession` PATCH with a note (per #17). |
| **Placement** | A top-level **Demo \| Policy Studio** switch in the header, with its own layout: stepper, cart and Learn panel. |
