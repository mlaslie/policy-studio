// Policy map nodes, ported from the demo's diagram/nodes.tsx (same look: badge, icon tile, title, chips, Model Armor
// shield, MCP tool rows). Every node has one target handle on the left ("in") and one source handle on the right
// ("out"); the lines always read left to right.
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { createContext, memo, useContext } from "react";
import type { CSSProperties } from "react";
import { ApiIcon, ArrowIcon, BookIcon, ClockIcon, CloudIcon, GatewayIcon, PencilIcon, PersonIcon, PinIcon, RegistryIcon, RobotIcon, ServerIcon, ShieldIcon, WarnIcon } from "../components/Icons";
import type { Chip } from "./graph";
import type { MNode, ToolState } from "./toFlow";
import { TITLE_MAX, shortLabel } from "./labels";

/** Actions a node can trigger (kept out of node data so it stays plain). */
export const MapActions = createContext<{ jump: (id: string) => void; unpin: (id: string) => void }>({ jump: () => undefined, unpin: () => undefined });

const H = ({ type, pos, id, style }: { type: "source" | "target"; pos: Position; id: string; style?: CSSProperties }) => (
  <Handle type={type} position={pos} id={id} isConnectable={false} className="hnd" style={style} />
);
const Handles = () => (
  <>
    <H type="target" pos={Position.Left} id="in" />
    <H type="source" pos={Position.Right} id="out" />
  </>
);

function Chips({ chips }: { chips?: Chip[] }) {
  if (!chips?.length) return null;
  return (
    <div className="node-chips">
      {chips.map((c) => (
        <span key={c.text} className={`chip chip-${c.tone} ${c.pending ? "chip-pending" : ""}`} title={c.title}>
          {c.pending && <ClockIcon size={11} />} {c.text}
        </span>
      ))}
    </div>
  );
}

/** A node you dragged keeps its place (saved per project, region and direction): a pin, and Unpin to send it back to
 *  the automatic layout. */
function Pin({ id, data }: { id: string; data: MNode["data"] }) {
  const { unpin } = useContext(MapActions);
  if (!data.pinned) return null;
  return (
    <button
      type="button"
      className="node-pin nodrag nopan"
      onClick={(e) => {
        e.stopPropagation();
        unpin(id);
      }}
      aria-label={`Unpin ${data.node.label}: back to the automatic layout`}
      title="Pinned where you dropped it. Click to unpin (back to the automatic layout)."
    >
      <PinIcon size={12} />
      <span className="node-pin-text">Unpin</span>
    </button>
  );
}

const cls = (d: MNode["data"], ...more: (string | false | undefined)[]) =>
  ["node", d.dim && "dim", d.hit && "hit", d.picked && "picked", d.filtered && "filtered", d.ring && `ring-${d.ring}`, d.node.pending && (d.node.pending.removed ? "pending-removed" : "pending"), ...more].filter(Boolean).join(" ");

/** A node the picker hides, drawn because a selected agent has a line to it. */
const Filtered = ({ data }: { data: MNode["data"] }) => (data.filtered ? <span className="node-filtered">(hidden by filter)</span> : null);

/** "Same agent" link between an Agent Runtime agent as a caller and as a registry entry. */
function SameAs({ id, label }: { id?: string; label: string }) {
  const { jump } = useContext(MapActions);
  if (!id) return null;
  return (
    <button
      type="button"
      className="node-open-btn nodrag nopan"
      onClick={(e) => {
        e.stopPropagation();
        jump(id);
      }}
      aria-label={`Same agent: go to ${label}`}
      title={`Same agent: go to its ${label}`}
    >
      <ArrowIcon size={12} />
    </button>
  );
}

const EngineNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  return (
    <div className={cls(data, "node-orch", !n.gateway && "unbound")}>
      <Handles />
      <Pin id={id} data={data} />
      <Filtered data={data} />
      <div className="node-badge badge-runtime">
        <span className="dot" /> Agent Runtime
      </div>
      <SameAs id={n.sameAs} label="registry entry" />
      <div className="node-head">
        <span className="node-icon icon-orch">
          <RobotIcon size={22} />
        </span>
        <div className="node-titles">
          <div className="node-title" title={n.label}>
            {n.label}
          </div>
          <div className="node-sub mono">{n.sub}</div>
        </div>
      </div>
      <Chips chips={n.chips} />
    </div>
  );
});

const GatewayNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  const none = n.kind === "no_gateway";
  const ma = n.modelArmor;
  const maTitle = ma?.enabled ? [`Model Armor${ma.dryRun ? " (dry run: screening, not blocking)" : ""}${ma.template ? `: template ${ma.template}` : ""}`, ...(ma.summary ?? [])].join("\n") : undefined;
  // A staged Model Armor change: a pending shield (dashed, with a clock), struck through when it's turned off.
  const shield = n.pending?.shield;
  const shieldTitle = shield ? `Model Armor ${shield.to === "on" ? "on" : "off"} (staged)${shield.template ? `: template ${shield.template}` : ""}` : undefined;
  return (
    <div className={cls(data, "node-gateway", none ? "faded" : "attached", n.mode === "DRY_RUN" && n.sub?.startsWith("Egress") && "dry")}>
      <Handles />
      <Pin id={id} data={data} />
      <Filtered data={data} />
      <div className="node-head">
        <span className="node-icon icon-gateway">
          <GatewayIcon size={22} />
        </span>
        <div className="node-titles">
          <div className="node-title" title={n.label}>
            {n.label}
          </div>
          <div className="node-sub">{n.sub}</div>
        </div>
      </div>
      <Chips chips={n.chips} />
      {shield ? (
        <div className={`ma-shield pending-${shield.to}`} title={shieldTitle} aria-label={shieldTitle}>
          <ShieldIcon size={20} />
          <span className="ma-shield-clock">
            <ClockIcon size={10} />
          </span>
        </div>
      ) : (
        ma?.enabled && (
          <div className={`ma-shield ${ma.dryRun ? "outlined" : ""}`} title={maTitle} aria-label={maTitle}>
            <ShieldIcon size={20} />
          </div>
        )
      )}
    </div>
  );
});

const PseudoNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  const pub = n.id === "pseudo:public";
  return (
    <div className={cls(data, "node-user", pub && "public")} title={n.members?.map((m) => m.label).join("\n")}>
      <Handles />
      <Pin id={id} data={data} />
      <Filtered data={data} />
      <div className="node-head">
        <span className={`node-icon ${n.kind === "client" ? "icon-client" : "icon-person"}`}>
          <PersonIcon size={20} />
        </span>
        <div className="node-titles">
          <div className="node-title">{n.label}</div>
          <div className="node-sub wrap-sub">{n.sub}</div>
        </div>
      </div>
      <Chips chips={n.chips} />
    </div>
  );
});

const DEST_BADGE: Record<string, string> = { a2a: "A2A", runtime_dest: "Agent Runtime", endpoint: "API endpoint", registry: "Registry-wide" };

const DestNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  const icon = n.kind === "endpoint" ? <ApiIcon size={20} /> : n.kind === "registry" ? <RegistryIcon size={20} /> : <RobotIcon size={20} />;
  const skills = n.skills ?? [];
  // Endpoints: shortened from the middle (the service name and the port both show); the full display name and URL on
  // hover and in the details panel.
  const ep = n.kind === "endpoint";
  const full = ep ? [n.displayName, n.url].filter(Boolean).join("\n") : n.label;
  return (
    <div className={cls(data, `node-dest node-${n.kind}`, n.unreadable && "unreadable")}>
      <Handles />
      <Pin id={id} data={data} />
      <Filtered data={data} />
      <div className={`node-badge ${n.kind === "registry" ? "" : "badge-cloudrun"}`}>
        {n.kind === "a2a" && <CloudIcon size={12} />} {DEST_BADGE[n.kind]}
      </div>
      {n.kind === "runtime_dest" && <SameAs id={n.sameAs} label="caller" />}
      <div className="node-head">
        <span className={`node-icon icon-${n.kind === "endpoint" ? "api" : n.kind === "registry" ? "registry" : "a2a"}`}>{icon}</span>
        <div className="node-titles">
          <div className={`node-title ${ep ? "mono-title" : ""}`} title={full}>
            {ep ? shortLabel(n.label, TITLE_MAX) : n.label}
          </div>
          <div className="node-sub mono" title={ep ? full : n.sub}>
            {ep && n.sub ? shortLabel(n.sub, TITLE_MAX + 1) : n.sub}
          </div>
        </div>
        {data.ring && <span className={`state-dot st-${data.ring}`} />}
      </div>
      {skills.length > 0 && (
        <div className="skills">
          {skills.slice(0, 3).map((s) => (
            <div key={s} className="skill">
              <span className="skill-tag">skill</span> {s}
            </div>
          ))}
          {skills.length > 3 && <div className="skill">+{skills.length - 3}</div>}
        </div>
      )}
      {n.unreadable && (
        <div className="node-chips">
          <span className="chip chip-red" title={n.unreadable}>
            <WarnIcon size={11} /> IAP policy couldn't be read
          </span>
        </div>
      )}
      {!n.unreadable && <Chips chips={n.chips} />}
    </div>
  );
});

const TOOL_TITLE: Record<ToolState, string> = { allowed: "allowed", denied: "denied", unknown: "can't be told here" };

const McpNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  const tools = n.tools ?? [];
  const destructive = tools.filter((t) => t.destructive).length;
  return (
    <div className={cls(data, "node-mcp", n.unreadable && "unreadable")}>
      <Handles />
      <Pin id={id} data={data} />
      <Filtered data={data} />
      <div className="node-badge badge-cloudrun">
        <CloudIcon size={12} /> MCP
      </div>
      <div className="node-head">
        <span className="node-icon icon-mcp">
          <ServerIcon size={20} />
        </span>
        <div className="node-titles">
          <div className="node-title" title={n.label}>
            {n.label}
          </div>
          <div className="node-sub mono" title={n.sub}>
            {n.sub}
          </div>
        </div>
        {data.ring && <span className={`state-dot st-${data.ring}`} />}
      </div>
      {data.expanded ? (
        <div className="tools">
          {tools.map((t) => {
            const st = data.toolStates?.[t.name];
            return (
              <div key={t.name} className={`tool-row ${st ? `st-${st}` : ""}`} title={`${t.name}: ${t.readOnly ? "read-only" : t.destructive ? "destructive" : "write"}${st ? `, ${TOOL_TITLE[st]}` : ""}`}>
                <span className={`tool-kind ${t.readOnly ? "ro" : "rw"}`}>{t.readOnly ? <BookIcon size={13} /> : <PencilIcon size={13} />}</span>
                <span className="tool-name mono">{t.name}</span>
                <span className={`tool-access ${t.readOnly ? "ro" : "rw"}`}>{t.readOnly ? "read" : "write"}</span>
                {st && <span className={`state-dot st-${st === "allowed" ? "allowed" : st === "denied" ? "blocked" : "conditional"}`} />}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="node-chips">
          <span className="chip">{tools.length} tools</span>
          {destructive > 0 && <span className="chip chip-red">{destructive} destructive</span>}
        </div>
      )}
      {n.unreadable ? (
        <div className="node-chips">
          <span className="chip chip-red" title={n.unreadable}>
            <WarnIcon size={11} /> IAP policy couldn't be read
          </span>
        </div>
      ) : (
        <Chips chips={n.chips} />
      )}
    </div>
  );
});

const GroupNode = memo(({ id, data }: NodeProps<MNode>) => (
  <div className={cls(data, "node-group")} title="Show these destinations">
    <Handles />
    <Pin id={id} data={data} />
    <Filtered data={data} />
    <div className="node-head">
      <span className="node-icon icon-registry">
        <ApiIcon size={18} />
      </span>
      <div className="node-titles">
        <div className="node-title">{data.node.label}</div>
        <div className="node-sub">{data.node.sub}</div>
      </div>
    </div>
  </div>
));

/** The collapsed Google API endpoints (view.ts): click (or Enter) ticks "Show Google API endpoints". */
const GoogleGroupNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  return (
    <div className={cls(data, "node-dest node-endpoint node-google")} title={`Show the ${n.grouped?.length ?? 0} Google API endpoints one by one`}>
      <Handles />
      <Pin id={id} data={data} />
      <Filtered data={data} />
      <div className="node-badge badge-cloudrun">API endpoints · collapsed</div>
      <div className="node-head">
        <span className="node-icon icon-api">
          <ApiIcon size={20} />
        </span>
        <div className="node-titles">
          <div className="node-title">{n.label}</div>
          <div className="node-sub">{n.sub}</div>
        </div>
        {data.ring && <span className={`state-dot st-${data.ring}`} />}
      </div>
      <Chips chips={n.chips} />
    </div>
  );
});

const SinkNode = memo(({ id, data }: NodeProps<MNode>) => (
  <div className={cls(data, "node-sink")}>
    <Handles />
    <Pin id={id} data={data} />
    <Filtered data={data} />
    <div className="node-head">
      <span className="node-icon icon-sink">
        <CloudIcon size={20} />
      </span>
      <div className="node-titles">
        <div className="node-title">{data.node.label}</div>
        <div className="node-sub">{data.node.sub}</div>
      </div>
    </div>
  </div>
));

const SectionNode = memo(({ data }: NodeProps<MNode>) => (
  <div className="node-section" style={{ width: data.width }}>
    {data.title}
  </div>
));

// Not "group": that's one of React Flow's built-in node types, and its wrapper (.react-flow__node-group) has built-in
// styles (a 150px box with padding, a dark border and a selection shadow) that showed behind the card.
export const nodeTypes = {
  engine: EngineNode,
  gateway: GatewayNode,
  pseudo: PseudoNode,
  dest: DestNode,
  mcp: McpNode,
  nogrants: GroupNode,
  google: GoogleGroupNode,
  sink: SinkNode,
  section: SectionNode,
};
