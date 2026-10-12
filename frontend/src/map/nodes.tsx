// Policy map nodes, ported from the demo's diagram/nodes.tsx (same look: badge, icon tile, title, chips, Model Armor
// shield, MCP tool rows). Every node has one target handle on the left ("in") and one source handle on the right
// ("out"); the lines always read left to right.
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { createContext, memo, useContext } from "react";
import type { CSSProperties } from "react";
import { ApiIcon, ArrowIcon, BookIcon, CloudIcon, GatewayIcon, PencilIcon, PersonIcon, RegistryIcon, RobotIcon, ServerIcon, ShieldIcon, WarnIcon } from "../components/Icons";
import type { Chip } from "./graph";
import type { MNode, ToolState } from "./toFlow";

/** Actions a node can trigger (kept out of node data so it stays plain). */
export const MapActions = createContext<{ jump: (id: string) => void }>({ jump: () => undefined });

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
        <span key={c.text} className={`chip chip-${c.tone}`} title={c.title}>
          {c.text}
        </span>
      ))}
    </div>
  );
}

const cls = (d: MNode["data"], ...more: (string | false | undefined)[]) => ["node", d.dim && "dim", d.hit && "hit", d.ring && `ring-${d.ring}`, ...more].filter(Boolean).join(" ");

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

const EngineNode = memo(({ data }: NodeProps<MNode>) => {
  const n = data.node;
  return (
    <div className={cls(data, "node-orch", !n.gateway && "unbound")}>
      <Handles />
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

const GatewayNode = memo(({ data }: NodeProps<MNode>) => {
  const n = data.node;
  const none = n.kind === "no_gateway";
  const ma = n.modelArmor;
  const maTitle = ma?.enabled ? [`Model Armor${ma.dryRun ? " (dry run: screening, not blocking)" : ""}${ma.template ? `: template ${ma.template}` : ""}`, ...(ma.summary ?? [])].join("\n") : undefined;
  return (
    <div className={cls(data, "node-gateway", none ? "faded" : "attached", n.mode === "DRY_RUN" && n.sub?.startsWith("Egress") && "dry")}>
      <Handles />
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
      {ma?.enabled && (
        <div className={`ma-shield ${ma.dryRun ? "outlined" : ""}`} title={maTitle} aria-label={maTitle}>
          <ShieldIcon size={20} />
        </div>
      )}
    </div>
  );
});

const PseudoNode = memo(({ data }: NodeProps<MNode>) => {
  const n = data.node;
  const pub = n.id === "pseudo:public";
  return (
    <div className={cls(data, "node-user", pub && "public")} title={n.members?.map((m) => m.label).join("\n")}>
      <Handles />
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

const DestNode = memo(({ data }: NodeProps<MNode>) => {
  const n = data.node;
  const icon = n.kind === "endpoint" ? <ApiIcon size={20} /> : n.kind === "registry" ? <RegistryIcon size={20} /> : <RobotIcon size={20} />;
  const skills = n.skills ?? [];
  return (
    <div className={cls(data, `node-dest node-${n.kind}`, n.unreadable && "unreadable")}>
      <Handles />
      <div className={`node-badge ${n.kind === "registry" ? "" : "badge-cloudrun"}`}>
        {n.kind === "a2a" && <CloudIcon size={12} />} {DEST_BADGE[n.kind]}
      </div>
      {n.kind === "runtime_dest" && <SameAs id={n.sameAs} label="caller" />}
      <div className="node-head">
        <span className={`node-icon icon-${n.kind === "endpoint" ? "api" : n.kind === "registry" ? "registry" : "a2a"}`}>{icon}</span>
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

const McpNode = memo(({ data }: NodeProps<MNode>) => {
  const n = data.node;
  const tools = n.tools ?? [];
  const destructive = tools.filter((t) => t.destructive).length;
  return (
    <div className={cls(data, "node-mcp", n.unreadable && "unreadable")}>
      <Handles />
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

const GroupNode = memo(({ data }: NodeProps<MNode>) => (
  <div className={cls(data, "node-group")} title="Show these destinations">
    <Handles />
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

const SinkNode = memo(({ data }: NodeProps<MNode>) => (
  <div className={cls(data, "node-sink")}>
    <Handles />
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

export const nodeTypes = {
  engine: EngineNode,
  gateway: GatewayNode,
  pseudo: PseudoNode,
  dest: DestNode,
  mcp: McpNode,
  group: GroupNode,
  sink: SinkNode,
  section: SectionNode,
};
