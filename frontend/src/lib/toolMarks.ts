// How an MCP tool row is marked wherever tools are listed (the map's cards, the preview, the builder's checklist,
// Inventory, the policy panel): its kind (read: blue book; write, destructive or not: amber pencil and WRITE pill) and,
// when an agent is selected, its state as a small text label at the row's right end (green "allowed", red "denied",
// a muted "?" when a condition can't be told here). Red is only ever "denied", never a tool's kind.

export type ToolState = "allowed" | "denied" | "unknown";

/** The label drawn at the row's right end. */
export const TOOL_STATE_TEXT: Record<ToolState, string> = { allowed: "allowed", denied: "denied", unknown: "?" };
/** The full meaning, for the row's aria-label and title. */
export const TOOL_STATE_WORDS: Record<ToolState, string> = { allowed: "allowed", denied: "denied", unknown: "can't be told here" };

/** The row's label, or null when there's no state (no agent selected): no label then. */
export const toolStateText = (st: ToolState | null | undefined): string | null => (st ? TOOL_STATE_TEXT[st] : null);

/** A tool's kind: read-only (readOnlyHint), or write (destructive ones are write too, said in words). */
export const toolKindWords = (t: { readOnly: boolean; destructive?: boolean }) => (t.readOnly ? "read-only" : t.destructive ? "destructive" : "write");

/** "search_tickets: read-only, allowed" — a row's aria-label (and the first line of its title). */
export const toolRowLabel = (name: string, t: { readOnly: boolean; destructive?: boolean }, st?: ToolState | null) =>
  `${name}: ${toolKindWords(t)}${st ? `, ${TOOL_STATE_WORDS[st]}` : ""}`;
