// MCP tool row marks (lib/toolMarks.ts): the kind tile (blue book, amber pencil), the READ / WRITE pill, and the
// allowed / denied / "?" label. Colours are the --tool-* tokens in styles.css.
import { BookIcon, PencilIcon } from "./Icons";
import { TOOL_STATE_TEXT, type ToolState } from "../lib/toolMarks";

/** The kind tile at the row's left: a blue book for read-only tools, an amber pencil for write ones. */
export const ToolKindIcon = ({ readOnly }: { readOnly: boolean }) => (
  <span className={`tool-kind ${readOnly ? "ro" : "rw"}`} aria-hidden="true">
    {readOnly ? <BookIcon size={13} /> : <PencilIcon size={13} />}
  </span>
);

/** The allowed / denied / "?" label at the row's right end; nothing without a state. The row's aria-label and title
 *  carry the full meaning, so the label itself is hidden from screen readers. */
export function ToolStateLabel({ st }: { st?: ToolState | null }) {
  if (!st) return null;
  return (
    <span className={`tool-state ts-${st}`} aria-hidden="true">
      {TOOL_STATE_TEXT[st]}
    </span>
  );
}
