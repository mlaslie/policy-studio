// MCP tool rows: the state label at the row's right end ("allowed", "denied", "?", none without a state), the row's
// full meaning for its aria-label and title, and tool names that stay inside the row next to the pill and the label.
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ToolKindIcon, ToolStateLabel } from "../components/ToolMarks";
import { FIT, fitText, type Measure } from "../map/fit";
import { toolLabelW, toolPillW, toolRoom } from "../map/layout";
import { TOOL_STATE_TEXT, toolKindWords, toolRowLabel, toolStateText, type ToolState } from "./toolMarks";

/** Every character is 0.6em wide (the estimate's monospace width, used for every font here: the widest case). */
const wide: Measure = (text, font) => text.length * Number(/([\d.]+)px/.exec(font)![1]) * 0.6;

describe("tool state label", () => {
  it("renders allowed, denied or ? for each state", () => {
    const cases: [ToolState, string][] = [
      ["allowed", "allowed"],
      ["denied", "denied"],
      ["unknown", "?"],
    ];
    for (const [st, text] of cases) {
      const html = renderToStaticMarkup(<ToolStateLabel st={st} />);
      expect(html).toContain(`class="tool-state ts-${st}"`);
      expect(html).toContain(`>${text}</span>`);
      expect(toolStateText(st)).toBe(text);
    }
  });

  it("renders no label without a state (no agent selected)", () => {
    expect(renderToStaticMarkup(<ToolStateLabel />)).toBe("");
    expect(renderToStaticMarkup(<ToolStateLabel st={null} />)).toBe("");
    expect(toolStateText(undefined)).toBeNull();
  });

  it("keeps the full meaning for the row's aria-label and title", () => {
    expect(toolRowLabel("search_tickets", { readOnly: true }, "allowed")).toBe("search_tickets: read-only, allowed");
    expect(toolRowLabel("close_ticket", { readOnly: false, destructive: true }, "denied")).toBe("close_ticket: destructive, denied");
    expect(toolRowLabel("create_ticket", { readOnly: false }, "unknown")).toBe("create_ticket: write, can't be told here");
    expect(toolRowLabel("create_ticket", { readOnly: false })).toBe("create_ticket: write");
  });
});

describe("tool kind", () => {
  it("marks read tools blue (ro) and write tools amber (rw), destructive ones too", () => {
    expect(renderToStaticMarkup(<ToolKindIcon readOnly />)).toContain('class="tool-kind ro"');
    expect(renderToStaticMarkup(<ToolKindIcon readOnly={false} />)).toContain('class="tool-kind rw"');
    expect(toolKindWords({ readOnly: false, destructive: true })).toBe("destructive");
  });
});

describe("tool names fit the row", () => {
  it("leaves less room for the name when a label follows the pill", () => {
    const bare = toolRoom([toolPillW("write", wide)]);
    for (const st of Object.keys(TOOL_STATE_TEXT) as ToolState[]) expect(toolRoom([toolPillW("write", wide), toolLabelW(TOOL_STATE_TEXT[st], wide)])).toBeLessThan(bare);
  });

  it("shortens a long name with an ellipsis so it stays inside the row", () => {
    const room = toolRoom([toolPillW("write", wide), toolLabelW("allowed", wide)]);
    expect(room).toBeGreaterThan(80);
    const f = fitText("bulk_reassign_tickets_between_queues", room, FIT.tool, "end", wide);
    expect(f.cut).toBe(true);
    expect(f.text.endsWith("…")).toBe(true);
    expect(f.size).toBe(FIT.tool.min);
    expect(wide(f.text, `400 ${f.size}px mono`)).toBeLessThanOrEqual(room);
    // a short one is drawn as it is
    expect(fitText("get_ticket", room, FIT.tool, "end", wide)).toEqual({ text: "get_ticket", size: 13, cut: false });
  });
});
