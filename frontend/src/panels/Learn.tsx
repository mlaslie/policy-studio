// Learn panel: a friendly explanation and mini diagram for the current step, plus the glossary.
import { useEffect, useRef, type ReactNode } from "react";
import { useStudio, type StepN } from "../store";
import { GLOSSARY } from "../lib/glossary";
import { BookIcon, ChevronIcon } from "../components/Icons";

type Node = { label: string; sub?: string; tone?: "agent" | "gw" | "dest" | "check" | "muted" };

/** Left-to-right flow of up to 4 boxes with arrows. Uses CSS variables so it works in light and dark. */
function Flow({ nodes, caption }: { nodes: Node[]; caption: string }) {
  const W = 300, H = 92, gap = 14;
  const bw = (W - gap * (nodes.length - 1)) / nodes.length;
  return (
    <figure className="flow">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={caption}>
        <defs>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0 0 10 5 0 10z" fill="var(--text-3)" />
          </marker>
        </defs>
        {nodes.map((n, i) => {
          const x = i * (bw + gap);
          return (
            <g key={i}>
              <rect x={x + 0.5} y={18.5} width={bw - 1} height={52} rx={10} className={`flow-box flow-${n.tone ?? "muted"}`} />
              <text x={x + bw / 2} y={n.sub ? 41 : 48} textAnchor="middle" className="flow-label">
                {n.label}
              </text>
              {n.sub && (
                <text x={x + bw / 2} y={57} textAnchor="middle" className="flow-sub">
                  {n.sub}
                </text>
              )}
              {i < nodes.length - 1 && <line x1={x + bw + 1} y1={44.5} x2={x + bw + gap - 1} y2={44.5} stroke="var(--text-3)" strokeWidth={1.5} markerEnd="url(#arr)" />}
            </g>
          );
        })}
      </svg>
      <figcaption>{caption}</figcaption>
    </figure>
  );
}

const LESSONS: Record<StepN, { title: string; body: ReactNode; flow: ReactNode }> = {
  0: {
    title: "Where are we looking?",
    body: (
      <>
        <p>Everything in Agent Gateway lives in a <b>project</b> and a <b>region</b>. Pick them once; every list, check and generated command uses them.</p>
        <p>Checking and building only <b>read</b> your project. Run locally, Policy Studio uses your own Google Cloud login (Application Default Credentials), so it sees exactly what you can see.</p>
        <p>The <b>mode badge</b> at the top says whether it can also apply changes: <b>Generate-only</b> on Cloud Run (you copy the commands), <b>Apply enabled</b> when run locally with working credentials.</p>
      </>
    ),
    flow: <Flow caption="Your login reads one project and region" nodes={[{ label: "You", sub: "gcloud login", tone: "agent" }, { label: "Policy Studio", sub: "read-only", tone: "check" }, { label: "Project", sub: "+ region", tone: "dest" }]} />,
  },
  1: {
    title: "What a gateway does",
    body: (
      <>
        <p>A gateway is a checkpoint. Agents don't call things directly any more; their traffic goes <b>through</b> the gateway, which checks it.</p>
        <p><b>Egress</b> checks calls your agents make. It is <b>deny by default</b>: an agent can only reach destinations it was granted. <b>Ingress</b> checks calls coming in, for example from Gemini Enterprise.</p>
        <p>An agent only gets these checks once it is <b>bound</b> to the gateway. Unbound agents call out directly, unchecked.</p>
      </>
    ),
    flow: <Flow caption="Egress: the gateway checks every outbound call" nodes={[{ label: "Agent", tone: "agent" }, { label: "Egress GW", sub: "IAP check", tone: "gw" }, { label: "MCP / A2A", sub: "API", tone: "dest" }]} />,
  },
  2: {
    title: "How Model Armor attaches",
    body: (
      <>
        <p>Model Armor reads the <b>content</b> of messages and blocks risky ones: prompt injection, leaked secrets, harmful text, bad links.</p>
        <p>A <b>template</b> holds the filter settings. A gateway uses it through a <b>CONTENT_AUTHZ</b> policy, so "turning Model Armor on" for a gateway means attaching that policy.</p>
        <p>On egress it screens MCP traffic only, not A2A calls.</p>
      </>
    ),
    flow: <Flow caption="Content is screened before it is forwarded" nodes={[{ label: "Prompt", tone: "agent" }, { label: "Gateway", sub: "CONTENT_AUTHZ", tone: "gw" }, { label: "Model Armor", sub: "template", tone: "check" }, { label: "Agent", tone: "dest" }]} />,
  },
  3: {
    title: "The registry is the guest list",
    body: (
      <>
        <p>The gateway only knows destinations that are in its <b>Agent Registry</b>: A2A agents, MCP servers and API endpoints.</p>
        <p>Each registry entry has its own IAM policy. Whoever holds <b>roles/iap.egressor</b> on it can reach it through the gateway. That's the "Who can reach it" list on each card.</p>
        <p>Your <b>source</b> agents are the Agent Runtime engines. Each has an <b>Agent Identity</b>: the long principal:// you grant access to.</p>
      </>
    ),
    flow: <Flow caption="A grant on a registry entry names who may reach it" nodes={[{ label: "Agent Identity", sub: "principal://…", tone: "agent" }, { label: "iap.egressor", sub: "role", tone: "check" }, { label: "Registry entry", sub: "agent / MCP / API", tone: "dest" }]} />,
  },
  4: {
    title: "How a grant is built",
    body: (
      <>
        <p>Every policy here is one IAM grant with four parts:</p>
        <ul>
          <li><b>Resource</b>: the destination being protected.</li>
          <li><b>Role</b>: always roles/iap.egressor, "may call it through the gateway".</li>
          <li><b>Member</b>: who gets access, usually one agent's identity.</li>
          <li><b>Condition</b> (optional): narrows it, e.g. only read-only tools.</li>
        </ul>
        <p>Conditions on MCP servers always allow an empty tool name <span className="mono">''</span>: that's how MCP setup calls (initialize, tools/list) look.</p>
      </>
    ),
    flow: <Flow caption="Member + role + resource (+ condition) = one grant" nodes={[{ label: "Who", sub: "member", tone: "agent" }, { label: "Role", sub: "egressor", tone: "check" }, { label: "What", sub: "resource", tone: "dest" }, { label: "How much", sub: "condition", tone: "gw" }]} />,
  },
  5: {
    title: "Same policy, four ways",
    body: (
      <>
        <p>Each staged item is rendered as <b>Terraform</b>, <b>gcloud</b>, <b>REST</b> (curl) and <b>Python</b>. They all do the same thing: pick the one your team uses.</p>
        <p>The <b>Diff</b> compares each item with what is in the project now: will it add something new, is it already there, or will it replace an existing grant?</p>
        <p>Nothing is changed in your project from here. Copy the commands or download the bundle and run it yourself, or (when Apply is enabled) continue to Apply.</p>
      </>
    ),
    flow: <Flow caption="Staged items become code you run" nodes={[{ label: "Cart", tone: "agent" }, { label: "Render", tone: "check" }, { label: "TF / gcloud", sub: "REST / Python", tone: "dest" }]} />,
  },
  6: {
    title: "Applying changes",
    body: (
      <>
        <p>When Policy Studio runs locally with working credentials, it can apply the cart for you. You type the project ID to confirm; removing access, detaching an agent or turning off Model Armor needs an extra tick.</p>
        <p>Each change is applied, then <b>read back</b> to verify it. Grants take seconds; binding an agent takes about 5 minutes and Model Armor about 4 (long-running operations).</p>
        <p>Every applied change records its inverse, so <b>Undo</b> stages it in the cart for you to apply the same way. On Cloud Run (generate-only), copy the commands instead.</p>
      </>
    ),
    flow: <Flow caption="Confirm, apply, verify, undo" nodes={[{ label: "Confirm", tone: "agent" }, { label: "Apply", tone: "gw" }, { label: "Read back", tone: "check" }, { label: "Undo", tone: "muted" }]} />,
  },
  7: {
    title: "Reading an audit",
    body: (
      <>
        <p>The audit lists every egress grant in plain English and flags common problems:</p>
        <ul>
          <li>agents not bound to an egress gateway (their grants are never checked),</li>
          <li>full access to MCP servers that have destructive tools,</li>
          <li>public members such as allAuthenticatedUsers,</li>
          <li>grants to agents that were deleted.</li>
        </ul>
        <p>Each finding can stage a fix in the cart, so you review it like any other change.</p>
      </>
    ),
    flow: <Flow caption="Findings turn into staged fixes" nodes={[{ label: "Project", tone: "agent" }, { label: "Audit", tone: "check" }, { label: "Finding", tone: "gw" }, { label: "Fix → cart", tone: "dest" }]} />,
  },
};

export function LearnPanel() {
  const { step, learnOpen, setLearnOpen, glossaryTerm } = useStudio();
  const lesson = LESSONS[step];
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!glossaryTerm || !learnOpen) return;
    const el = ref.current?.querySelector<HTMLElement>(`[data-term="${glossaryTerm}"]`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.remove("flash");
      void el.offsetWidth;
      el.classList.add("flash");
      (el.querySelector("details") as HTMLDetailsElement | null)?.setAttribute("open", "");
    }
  }, [glossaryTerm, learnOpen]);

  return (
    <section className={`learn ${learnOpen ? "open" : ""}`} aria-label="Learn">
      <button className="rail-head" aria-expanded={learnOpen} onClick={() => setLearnOpen(!learnOpen)}>
        <BookIcon size={16} />
        <span className="rail-title">Learn</span>
        <span className="rail-sub">{lesson.title}</span>
        <ChevronIcon size={18} className="chev" />
      </button>
      {learnOpen && (
        <div className="learn-body" ref={ref}>
          <h3>{lesson.title}</h3>
          {lesson.flow}
          <div className="learn-text">{lesson.body}</div>
          <h4 className="gloss-head">Glossary</h4>
          <dl className="glossary">
            {Object.entries(GLOSSARY).map(([k, g]) => (
              <div key={k} data-term={k} className={`gloss-item ${glossaryTerm === k ? "current" : ""}`}>
                <details open={glossaryTerm === k}>
                  <summary>
                    <dt>{g.term}</dt>
                    <dd className="gloss-short">{g.short}</dd>
                  </summary>
                  <dd className="gloss-long">{g.long}</dd>
                </details>
              </div>
            ))}
          </dl>
        </div>
      )}
    </section>
  );
}
