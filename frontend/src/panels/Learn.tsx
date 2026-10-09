// Learn panel (collapsible, resizable right rail): a friendly explanation and mini diagram for the current step, plus the glossary.
import { useCallback, useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { useStudio, type StepN } from "../store";
import { GLOSSARY } from "../lib/glossary";
import { BookIcon, ChevronIcon } from "../components/Icons";
import { Tip } from "../components/Tooltip";
import { load, save } from "../lib/util";

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

export const RAIL_MIN = 240;
export const RAIL_MAX = 560;
export const RAIL_DEFAULT = 330;
export const RAIL_COLLAPSED = 36;
const SNAP = 180; // dragging narrower than this collapses the panel
const KEY_STEP = 16;

/** Widest the rail may be right now, so the center column keeps at least ~500px at 1280. */
function maxWidth() {
  const stepper = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--stepper-w")) || 224;
  return Math.max(RAIL_MIN, Math.min(RAIL_MAX, window.innerWidth - stepper - 520));
}
const clamp = (w: number) => Math.round(Math.min(maxWidth(), Math.max(RAIL_MIN, w)));

/** Rail width (persisted) + collapsed state (the store's learnOpen, persisted). Returns the CSS width. */
export function useRailWidth() {
  const { learnOpen } = useStudio();
  const [width, setWidthState] = useState<number>(() => {
    const w = load<number>("studio.learnWidth", RAIL_DEFAULT);
    return typeof w === "number" && isFinite(w) ? Math.min(RAIL_MAX, Math.max(RAIL_MIN, w)) : RAIL_DEFAULT;
  });
  const setWidth = useCallback((w: number) => {
    setWidthState(w);
    save("studio.learnWidth", w);
  }, []);
  // Re-clamp when the window shrinks so the center never scrolls sideways.
  const [, force] = useState(0);
  useEffect(() => {
    const on = () => force((n) => n + 1);
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, []);
  const effective = learnOpen ? clamp(width) : RAIL_COLLAPSED;
  return { width, setWidth, effective };
}

function ResizeHandle({ width, setWidth }: { width: number; setWidth: (w: number) => void }) {
  const { learnOpen, setLearnOpen } = useStudio();
  const drag = useRef<{ x: number; w: number; orig: number; moved: boolean } | null>(null);
  const [dragging, setDragging] = useState(false);
  const shown = learnOpen ? clamp(width) : RAIL_COLLAPSED;

  const onPointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    e.preventDefault();
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    drag.current = { x: e.clientX, w: shown, orig: width, moved: false };
    setDragging(true);
    document.body.classList.add("resizing");
  };
  const onPointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d) return;
    const raw = d.w + (d.x - e.clientX);
    if (Math.abs(d.x - e.clientX) > 2) d.moved = true;
    if (!d.moved) return;
    if (raw < SNAP) {
      // Snap to collapsed, and remember the width from before the drag for the next expand.
      if (learnOpen) setLearnOpen(false);
      if (width !== d.orig) setWidth(d.orig);
    } else {
      if (!learnOpen) setLearnOpen(true);
      setWidth(clamp(raw));
    }
  };
  const end = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (!drag.current) return;
    drag.current = null;
    setDragging(false);
    document.body.classList.remove("resizing");
    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {
      /* already released */
    }
  };
  const onKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const delta = (e.key === "ArrowLeft" ? 1 : -1) * (e.shiftKey ? KEY_STEP * 4 : KEY_STEP);
      if (!learnOpen) {
        if (delta > 0) setLearnOpen(true);
        return;
      }
      setWidth(clamp(clamp(width) + delta));
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      setLearnOpen(!learnOpen);
    } else if (e.key === "Home") {
      e.preventDefault();
      setLearnOpen(true);
      setWidth(RAIL_MIN);
    } else if (e.key === "End") {
      e.preventDefault();
      setLearnOpen(true);
      setWidth(clamp(RAIL_MAX));
    }
  };

  return (
    <Tip tip="Drag to resize the Learn panel; drag far right to collapse it. Double-click resets the width. Keyboard: Left/Right resize, Enter collapses or expands." block className="rail-handle-tip">
      <div
        className={`rail-handle ${dragging ? "dragging" : ""}`}
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize Learn panel"
        aria-controls="learn-panel"
        aria-valuenow={shown}
        aria-valuemin={RAIL_COLLAPSED}
        aria-valuemax={RAIL_MAX}
        aria-valuetext={learnOpen ? `${shown} pixels wide` : "collapsed"}
        tabIndex={0}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={end}
        onPointerCancel={end}
        onDoubleClick={() => {
          setLearnOpen(true);
          setWidth(RAIL_DEFAULT);
        }}
        onKeyDown={onKeyDown}
      >
        <span className="rail-grip" aria-hidden="true" />
      </div>
    </Tip>
  );
}

export function LearnPanel({ width, setWidth }: { width: number; setWidth: (w: number) => void }) {
  const { step, learnOpen, setLearnOpen, glossaryTerm } = useStudio();
  const lesson = LESSONS[step];
  const ref = useRef<HTMLDivElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);
  const strip = useRef<HTMLButtonElement>(null);
  const wasOpen = useRef(learnOpen);

  // Keep focus on the matching toggle when the panel collapses/expands from a toggle button.
  useEffect(() => {
    if (wasOpen.current === learnOpen) return;
    const active = document.activeElement;
    if (active === toggle.current || active === strip.current || active === document.body) {
      requestAnimationFrame(() => (learnOpen ? toggle.current : strip.current)?.focus({ preventScroll: true }));
    }
    wasOpen.current = learnOpen;
  }, [learnOpen]);

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
    <aside className={`rail ${learnOpen ? "" : "collapsed"}`} aria-label="Learn">
      <ResizeHandle width={width} setWidth={setWidth} />
      {learnOpen ? (
        <section className="learn open" id="learn-panel">
          <div className="rail-head static">
            <BookIcon size={16} />
            <span className="rail-title">Learn</span>
            <span className="rail-sub">{lesson.title}</span>
            <Tip tip="Collapse the Learn panel to a slim strip. Your width is kept." placement="bottom">
              <button ref={toggle} type="button" className="icon-btn rail-toggle" aria-expanded={true} aria-controls="learn-panel" aria-label="Collapse Learn panel" onClick={() => setLearnOpen(false)}>
                <ChevronIcon size={18} />
              </button>
            </Tip>
          </div>
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
        </section>
      ) : (
        <Tip tip={`Expand the Learn panel: ${lesson.title}.`}>
          <button ref={strip} type="button" className="rail-strip" aria-expanded={false} aria-controls="learn-panel" aria-label={`Expand Learn panel: ${lesson.title}`} onClick={() => setLearnOpen(true)}>
            <ChevronIcon size={16} className="rail-strip-chev" />
            <BookIcon size={16} />
            <span className="rail-strip-label">Learn</span>
          </button>
        </Tip>
      )}
    </aside>
  );
}
