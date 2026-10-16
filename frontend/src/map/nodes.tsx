// Policy map nodes, ported from the demo's diagram/nodes.tsx (same look: badge, icon tile, title, chips, Model Armor
// shield, MCP tool rows). Every node has one target handle on the left ("in") and one source handle on the right
// ("out"); the lines always read left to right.
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { createContext, memo, useContext, useSyncExternalStore } from "react";
import type { CSSProperties, ReactNode } from "react";
import { ApiIcon, ArrowIcon, ClockIcon, CloudIcon, GatewayIcon, LockIcon, PersonIcon, PinIcon, RegistryIcon, RobotIcon, ServerIcon, ShieldIcon, WarnIcon } from "../components/Icons";
import { FIT, fitText, fontEpoch, onFontEpoch, type Cut, type FitStyle } from "./fit";
import type { Chip, PNodeKind } from "./graph";
import { W, chipShown, skillRoom, titleRoom, toolLabelW, toolPillW, toolRoom } from "./layout";
import type { MNode } from "./toFlow";
import { toolRowLabel, toolStateText } from "../lib/toolMarks";
import { ToolKindIcon, ToolStateLabel } from "../components/ToolMarks";

/** Actions a node can trigger (kept out of node data so it stays plain). */
export const MapActions = createContext<{ jump: (id: string) => void; unpin: (id: string) => void; openPicker: () => void }>({ jump: () => undefined, unpin: () => undefined, openPicker: () => undefined });

const H = ({ type, pos, id, style }: { type: "source" | "target"; pos: Position; id: string; style?: CSSProperties }) => (
  <Handle type={type} position={pos} id={id} isConnectable={false} className="hnd" style={style} />
);
const Handles = () => (
  <>
    <H type="target" pos={Position.Left} id="in" />
    <H type="source" pos={Position.Right} id="out" />
  </>
);

/** Re-fit when web fonts finish loading (fit.ts measures with the real glyphs then). */
const useFontEpoch = () => useSyncExternalStore(onFontEpoch, fontEpoch, fontEpoch);

/** Shown text and, when it was shortened, the full text for screen readers (the tooltip has it too). */
const Shown = ({ text, full }: { text: string; full: string }) =>
  text === full ? (
    <>{text}</>
  ) : (
    <>
      <span aria-hidden="true">{text}</span>
      <span className="sr-only">{full}</span>
    </>
  );

/** One line of card text fitted to its room (fit.ts): the font shrinks to its style's minimum, then the text is
 *  shortened (end ellipsis for names, middle for hosts and ids). The full text stays in the tooltip. */
function Fit({ text, room, style, cut = "end", className, title }: { text?: string | null; room: number; style: FitStyle; cut?: Cut; className: string; title?: string }) {
  useFontEpoch();
  const full = text ?? "";
  const f = fitText(full, room, style, cut);
  return (
    <div className={className} title={title ?? (full || undefined)} style={f.size !== style.size ? { fontSize: f.size } : undefined}>
      <Shown text={f.text} full={full} />
    </div>
  );
}

/** A card's title and subtitle, fitted to the room beside the icon (less the verdict dot when there is one). */
function Titles({ kind, title, sub, dot, titleStyle = FIT.title, subStyle = FIT.sub, titleCut = "end", subCut = "end", titleTip, subTip, wrapSub }: {
  kind: PNodeKind;
  title: string;
  sub?: string | null;
  dot?: boolean;
  titleStyle?: FitStyle;
  subStyle?: FitStyle;
  titleCut?: Cut;
  subCut?: Cut;
  titleTip?: string;
  subTip?: string;
  /** Long descriptions (pseudo callers) wrap instead; the card grows. */
  wrapSub?: boolean;
}) {
  const room = titleRoom(kind, dot);
  return (
    <div className="node-titles">
      <Fit className={`node-title ${titleStyle.mono ? "mono-title" : ""}`} text={title} room={room} style={titleStyle} cut={titleCut} title={titleTip} />
      {wrapSub ? <div className="node-sub wrap-sub">{sub}</div> : <Fit className={`node-sub ${subStyle.mono ? "mono" : ""}`} text={sub} room={room} style={subStyle} cut={subCut} title={subTip} />}
    </div>
  );
}

/** Summary chips: they wrap onto rows inside the card; long ones show their short form (labels.ts chipLabel) or are
 *  shortened to the card's width, with the full text in the tooltip. */
function Chips({ chips, kind }: { chips?: Chip[]; kind: PNodeKind }) {
  useFontEpoch();
  if (!chips?.length) return null;
  return (
    <div className="node-chips">
      {chips.map((c) => {
        const shown = chipShown(c, kind).text;
        const tip = [shown !== c.text && c.text, c.title].filter(Boolean).join("\n") || undefined;
        return (
          <span key={c.text} className={`chip chip-${c.tone} ${c.pending ? "chip-pending" : ""}`} title={tip}>
            {c.pending && <ClockIcon size={11} />}
            {c.icon === "lock" && <LockIcon size={11} />}
            <span className="chip-text">
              <Shown text={shown} full={c.text} />
            </span>
          </span>
        );
      })}
    </div>
  );
}

/** The card's width (layout.ts W): the room text is fitted into is worked out from it. */
const box = (k: PNodeKind): CSSProperties => ({ width: W[k] });

/** The top-right corner of a card: the pin (Unpin) and the "same agent" arrow, side by side, clear of the type badge
 *  on the left. */
const Corner = ({ children }: { children: ReactNode }) => <div className="node-corner">{children}</div>;

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

// "node-picked", not "picked": a global .picked (the Builder's chosen-agent box: display flex, padding, a border) would
// lay a selected agent's card out as a row, its chips spilling out past the border.
const cls = (d: MNode["data"], ...more: (string | false | undefined)[]) =>
  ["node", d.dim && "dim", d.hit && "hit", d.picked && "node-picked", d.ring && `ring-${d.ring}`, d.node.pending && (d.node.pending.removed ? "pending-removed" : "pending"), ...more].filter(Boolean).join(" ");

/** A selected caller's lines left off the map with the hidden objects at their other end: a muted note that opens the
 *  picker. (Its chips count the policy, not the view, so they don't change.) */
function HiddenNote({ n }: { n: MNode["data"]["node"] }) {
  const { openPicker } = useContext(MapActions);
  if (!n.hiddenLines) return null;
  const what = `${n.hiddenLines} ${n.hiddenLines === 1 ? "line" : "lines"} to hidden objects`;
  return (
    <button
      type="button"
      className="node-hidden-note nodrag nopan"
      onClick={(e) => {
        e.stopPropagation();
        openPicker();
      }}
      title={`${what}: a type filter or the picker hides the object at the other end. Click to open the picker.`}
      aria-label={`${what}. Open the picker`}
    >
      {what} · <span className="node-hidden-show">show</span>
    </button>
  );
}

/** Changed by an apply that may still be settling (map/settling.ts): a clock with when it was applied. Not a button; the
 *  node's accessible name carries the same text. */
const Settling = ({ text }: { text?: string }) =>
  text ? (
    <span className="node-settling" title={text} aria-hidden="true">
      <ClockIcon size={12} />
    </span>
  ) : null;

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
    <div className={cls(data, "node-orch", !n.gateway && "unbound")} style={box(n.kind)}>
      <Handles />
      <Corner>
        <Settling text={data.settling} />
        <Pin id={id} data={data} />
        <SameAs id={n.sameAs} label="registry entry" />
      </Corner>
      <div className="node-badge badge-runtime">
        <span className="dot" /> Agent Runtime
      </div>
      <div className="node-head">
        <span className="node-icon icon-orch">
          <RobotIcon size={22} />
        </span>
        <Titles kind={n.kind} title={n.label} sub={n.sub} subStyle={FIT.monoSub} subCut="middle" />
      </div>
      <Chips chips={n.chips} kind={n.kind} />
      <HiddenNote n={n} />
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
    <div className={cls(data, "node-gateway", none ? "faded" : "attached", n.mode === "DRY_RUN" && n.sub?.startsWith("Egress") && "dry")} style={box(n.kind)}>
      <Handles />
      <Corner>
        <Settling text={data.settling} />
        <Pin id={id} data={data} />
      </Corner>
      <div className="node-head">
        <span className="node-icon icon-gateway">
          <GatewayIcon size={22} />
        </span>
        <Titles kind={n.kind} title={n.label} sub={n.sub} />
      </div>
      <Chips chips={n.chips} kind={n.kind} />
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
    <div className={cls(data, "node-user", pub && "public")} style={box(n.kind)} title={n.members?.map((m) => m.label).join("\n")}>
      <Handles />
      <Corner>
        <Pin id={id} data={data} />
      </Corner>
      <div className="node-head">
        <span className={`node-icon ${n.kind === "client" ? "icon-client" : "icon-person"}`}>
          <PersonIcon size={20} />
        </span>
        <Titles kind={n.kind} title={n.label} sub={n.sub} wrapSub />
      </div>
      <Chips chips={n.chips} kind={n.kind} />
      <HiddenNote n={n} />
    </div>
  );
});

/** A skill's name, shortened to fit its pill (the full name in the pill's tooltip). */
function SkillName({ kind, name }: { kind: PNodeKind; name: string }) {
  useFontEpoch();
  const f = fitText(name, skillRoom(kind), FIT.skill, "end");
  return (
    <span className="skill-name">
      <Shown text={f.text} full={name} />
    </span>
  );
}

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
    <div className={cls(data, `node-dest node-${n.kind}`, n.unreadable && "unreadable")} style={box(n.kind)}>
      <Handles />
      <Corner>
        <Pin id={id} data={data} />
        {n.kind === "runtime_dest" && <SameAs id={n.sameAs} label="caller" />}
      </Corner>
      <div className={`node-badge ${n.kind === "registry" ? "" : "badge-cloudrun"}`}>
        {n.kind === "a2a" && <CloudIcon size={12} />} {DEST_BADGE[n.kind]}
      </div>
      <div className="node-head">
        <span className={`node-icon icon-${n.kind === "endpoint" ? "api" : n.kind === "registry" ? "registry" : "a2a"}`}>{icon}</span>
        <Titles
          kind={n.kind}
          title={n.label}
          sub={n.sub}
          dot={!!data.ring}
          titleStyle={ep ? FIT.monoTitle : FIT.title}
          titleCut={ep ? "host" : "end"}
          subStyle={FIT.monoSub}
          subCut={ep ? "host" : "middle"}
          titleTip={full}
          subTip={ep ? full : undefined}
        />
        {data.ring && <span className={`state-dot st-${data.ring}`} />}
      </div>
      {skills.length > 0 && (
        <div className="skills">
          {skills.slice(0, 3).map((s) => (
            <div key={s} className="skill" title={s}>
              <span className="skill-tag">skill</span>
              <SkillName kind={n.kind} name={s} />
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
      {!n.unreadable && <Chips chips={n.chips} kind={n.kind} />}
    </div>
  );
});

/** A tool row's name, fitted to the room the pill and the state label leave (layout.ts toolRoom): it shrinks to 11.5px,
 *  then ends in an ellipsis; the full name is in the row's tooltip and aria-label. */
export const ToolName = ({ name, room, title }: { name: string; room: number; title: string }) => <Fit className="tool-name mono" text={name} room={room} style={FIT.tool} title={title} />;

const McpNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  const tools = n.tools ?? [];
  // the rows Show: Allows / Denies leaves (view.ts shownTools), every tool otherwise
  const rows = n.shownTools ? tools.filter((t) => n.shownTools!.includes(t.name)) : tools;
  const destructive = tools.filter((t) => t.destructive).length;
  return (
    <div className={cls(data, "node-mcp", n.unreadable && "unreadable")} style={box(n.kind)}>
      <Handles />
      <Corner>
        <Pin id={id} data={data} />
      </Corner>
      <div className="node-badge badge-cloudrun">
        <CloudIcon size={12} /> MCP
      </div>
      <div className="node-head">
        <span className="node-icon icon-mcp">
          <ServerIcon size={20} />
        </span>
        <Titles kind={n.kind} title={n.label} sub={n.sub} dot={!!data.ring} subStyle={FIT.monoSub} subCut="middle" />
        {data.ring && <span className={`state-dot st-${data.ring}`} />}
      </div>
      {data.expanded ? (
        <div className="tools" role="list">
          {rows.map((t) => {
            const st = data.toolStates?.[t.name];
            const per = data.toolAgents?.[t.name];
            const label = toolRowLabel(t.name, t, st);
            const title = `${label}${per ? `\n${per}` : ""}`;
            const pill = t.readOnly ? "read" : "write";
            return (
              <div key={t.name} role="listitem" className={`tool-row ${st ? `st-${st}` : ""}`} aria-label={label} title={title}>
                <ToolKindIcon readOnly={t.readOnly} />
                <ToolName name={t.name} room={toolRoom([toolPillW(pill), ...(st ? [toolLabelW(toolStateText(st)!)] : [])])} title={title} />
                <span className={`tool-access ${t.readOnly ? "ro" : "rw"}`} aria-hidden="true">
                  {pill}
                </span>
                <ToolStateLabel st={st} />
              </div>
            );
          })}
        </div>
      ) : (
        <div className="node-chips">
          <span className="chip">{tools.length} tools</span>
          {destructive > 0 && <span className="chip chip-write">{destructive} destructive</span>}
        </div>
      )}
      {n.unreadable ? (
        <div className="node-chips">
          <span className="chip chip-red" title={n.unreadable}>
            <WarnIcon size={11} /> IAP policy couldn't be read
          </span>
        </div>
      ) : (
        <Chips chips={n.chips} kind={n.kind} />
      )}
    </div>
  );
});

const GroupNode = memo(({ id, data }: NodeProps<MNode>) => (
  <div className={cls(data, "node-group")} style={box(data.node.kind)} title="Show these destinations">
    <Handles />
    <Corner>
      <Pin id={id} data={data} />
    </Corner>
    <div className="node-head">
      <span className="node-icon icon-registry">
        <ApiIcon size={18} />
      </span>
      <Titles kind={data.node.kind} title={data.node.label} sub={data.node.sub} />
    </div>
  </div>
));

/** The collapsed Google API endpoints (view.ts): click (or Enter) ticks "Show Google API endpoints". */
const GoogleGroupNode = memo(({ id, data }: NodeProps<MNode>) => {
  const n = data.node;
  return (
    <div className={cls(data, "node-dest node-endpoint node-google")} style={box(n.kind)} title={`Show the ${n.grouped?.length ?? 0} Google API endpoints one by one`}>
      <Handles />
      <Corner>
        <Pin id={id} data={data} />
      </Corner>
      <div className="node-badge badge-cloudrun">API endpoints · collapsed</div>
      <div className="node-head">
        <span className="node-icon icon-api">
          <ApiIcon size={20} />
        </span>
        <Titles kind={n.kind} title={n.label} sub={n.sub} dot={!!data.ring} />
        {data.ring && <span className={`state-dot st-${data.ring}`} />}
      </div>
      <Chips chips={n.chips} kind={n.kind} />
    </div>
  );
});

const SinkNode = memo(({ id, data }: NodeProps<MNode>) => (
  <div className={cls(data, "node-sink")} style={box(data.node.kind)}>
    <Handles />
    <Corner>
      <Pin id={id} data={data} />
    </Corner>
    <div className="node-head">
      <span className="node-icon icon-sink">
        <CloudIcon size={20} />
      </span>
      <Titles kind={data.node.kind} title={data.node.label} sub={data.node.sub} />
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
