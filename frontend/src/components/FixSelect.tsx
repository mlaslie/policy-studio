// Multi-select for lists of fix commands: a checkbox per row that has a fix, and a toolbar with
// "Select all missing", "Clear", "Copy selected (N)" and "Download as .sh". The copied script keeps
// display order, drops duplicate commands and puts a "# <title>" comment above each one.
import { useEffect, useMemo, useRef, useState } from "react";
import { copyText } from "../lib/util";
import { downloadBlob } from "../lib/zip";
import { CheckIcon, CopyIcon, DownloadIcon } from "./Icons";

export type FixRow = { key: string; title: string; fix?: string | null; /** error / warn / not granted */ missing: boolean };

export type FixSelection = {
  rows: FixRow[];
  selected: Set<string>;
  toggle: (key: string) => void;
  selectMissing: () => void;
  clear: () => void;
  /** One block per selected row (title + its not-yet-seen commands), in display order. */
  commands: { title: string; fix: string }[];
};

export function useFixSelection(rows: FixRow[]): FixSelection {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const fixable = useMemo(() => rows.filter((r) => r.fix), [rows]);
  // Drop selections for rows that disappeared (e.g. after Sync).
  const keys = fixable.map((r) => r.key).join("|");
  useEffect(() => {
    setSelected((s) => {
      const live = new Set(fixable.map((r) => r.key));
      const next = new Set([...s].filter((k) => live.has(k)));
      return next.size === s.size ? s : next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys]);
  const commands = useMemo(() => {
    // A fix may hold several commands, one per line: split them so identical commands appear once.
    const seen = new Set<string>();
    const blocks: { title: string; fix: string }[] = [];
    for (const r of fixable) {
      if (!selected.has(r.key)) continue;
      const fresh = splitCommands(r.fix!).filter((c) => !seen.has(c));
      fresh.forEach((c) => seen.add(c));
      if (fresh.length) blocks.push({ title: r.title, fix: fresh.join("\n") });
    }
    return blocks;
  }, [fixable, selected]);
  return {
    rows,
    selected,
    commands,
    toggle: (k) =>
      setSelected((s) => {
        const n = new Set(s);
        if (n.has(k)) n.delete(k);
        else n.add(k);
        return n;
      }),
    selectMissing: () => setSelected(new Set(fixable.filter((r) => r.missing).map((r) => r.key))),
    clear: () => setSelected(new Set()),
  };
}

/** Lines of a fix that are commands (blank lines and # comments dropped). */
export function splitCommands(fix: string): string[] {
  return fix
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}
export const countCommands = (blocks: { fix: string }[]) => blocks.reduce((n, b) => n + splitCommands(b.fix).length, 0);

export function fixScript(cmds: { title: string; fix: string }[], header = false): string {
  const body = cmds.map((c) => `# ${c.title.replace(/\s*\n\s*/g, " ")}\n${c.fix}`).join("\n\n");
  return header ? `#!/usr/bin/env bash\nset -euo pipefail\n\n${body}\n` : `${body}\n`;
}

export function FixToolbar({ sel, filename = "fix.sh", label }: { sel: FixSelection; filename?: string; label: string }) {
  const [st, setSt] = useState<{ kind: "ok" | "fail"; n: number } | null>(null);
  const t = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(t.current), []);
  const fixable = sel.rows.filter((r) => r.fix);
  if (!fixable.length) return null;
  const missing = fixable.filter((r) => r.missing).length;
  const n = countCommands(sel.commands);
  const copy = async () => {
    const ok = await copyText(fixScript(sel.commands));
    setSt({ kind: ok ? "ok" : "fail", n });
    window.clearTimeout(t.current);
    t.current = window.setTimeout(() => setSt(null), 2200);
  };
  const download = () => downloadBlob(new Blob([fixScript(sel.commands, true)], { type: "text/x-shellscript" }), filename);
  return (
    <div className="fix-toolbar" role="toolbar" aria-label={`${label}: fix commands`}>
      <button type="button" className="link-btn small" onClick={sel.selectMissing} disabled={!missing} title={missing ? `Select every row that needs a fix (${missing})` : "Nothing is missing"}>
        Select all missing{missing ? ` (${missing})` : ""}
      </button>
      <button type="button" className="link-btn small" onClick={sel.clear} disabled={!sel.selected.size}>
        Clear
      </button>
      <span className="grow" />
      <button
        type="button"
        className={`mini-btn ${st?.kind === "ok" ? "copied" : ""} ${st?.kind === "fail" ? "copy-failed" : ""}`}
        onClick={copy}
        disabled={!n}
        title={n ? "Copy the selected fix commands as one script" : "Select one or more rows first"}
      >
        {st?.kind === "ok" ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
        <span aria-live="polite">{st?.kind === "ok" ? `Copied ${st.n} command${st.n === 1 ? "" : "s"}` : st?.kind === "fail" ? "Copy failed" : `Copy selected (${n})`}</span>
      </button>
      <button type="button" className="mini-btn" onClick={download} disabled={!n} title={n ? `Download the selected commands as ${filename}` : "Select one or more rows first"}>
        <DownloadIcon size={14} />
        <span>.sh</span>
      </button>
    </div>
  );
}

export function FixCheck({ sel, row }: { sel: FixSelection; row: FixRow }) {
  if (!row.fix) return <span className="fix-check-spacer" aria-hidden="true" />;
  return (
    <input
      type="checkbox"
      className="fix-check"
      checked={sel.selected.has(row.key)}
      onChange={() => sel.toggle(row.key)}
      aria-label={`Select the fix for: ${row.title}`}
      title="Include this fix in “Copy selected”"
    />
  );
}
