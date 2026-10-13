// The map's object picker (picker.ts): a button ("Objects: 3 of 42") that opens a popover with the quick toggles, a
// text filter, Select all / Clear, the objects grouped by type (each group with a count and a checkbox), and Cancel /
// Apply. Each row's checkbox is read off the map (pickerStatus): checked = on the map, unchecked with the reason
// ("hidden: no grants") when a filter hides it, "manual" when checking it overrode one. It edits a draft: the rows
// show the draft right away, the map changes on Apply; Cancel and Esc drop the draft. A click outside closes it when
// nothing is pending (with pending changes it stays open and asks for Apply or Cancel); a click on the canvas never
// closes it, so selecting agents there shows in the rows (the draft is rebased, rebaseDraft).
// Keyboard: the button opens it (focus goes to the filter); arrows move through the checkboxes, Space toggles one,
// Enter applies, Esc cancels. Enter in the filter with a single match does "Only this" and Apply.
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { ChevronIcon, SearchIcon } from "../components/Icons";
import { Tip } from "../components/Tooltip";
import { plural } from "../lib/util";
import {
  HIDDEN_LABEL,
  checkState,
  countOn,
  enterInFilter,
  filterItems,
  groupItems,
  isTypeGroup,
  onlyThis,
  pickerStatus,
  rebaseDraft,
  samePicker,
  setItems,
  setQuick,
  toggleItem,
  toggleSelected,
  toggleTypes,
  type PickItem,
  type PickerEnv,
  type PickerState,
  type Statuses,
} from "./picker";

type Props = {
  items: PickItem[];
  value: PickerState;
  /** The rest of what decides the map (the graph, the toolbar's filters, Changes only, the node in the panel). */
  env: PickerEnv;
  /** `value`'s statuses (MapStep has them from the map's own view). */
  statuses: Statuses;
  /** Egress only: the "Show Google API endpoints" toggle, and the type group checkboxes (type filters). */
  google: boolean;
  /** `focus`: the one object "Only this" (or Enter on a single match) left on, to reveal and center. */
  onApply: (next: PickerState, focus: string | null) => void;
};

export default function ObjectPicker({ items, value, env, statuses, google, onApply }: Props) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<PickerState>(value);
  /** The state the draft started from (or was last rebased on). */
  const base = useRef<PickerState>(value);
  const [nudge, setNudge] = useState(false);
  const [query, setQuery] = useState("");
  const [only, setOnly] = useState<string | null>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const filter = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const id = useId();
  const shown = useMemo(() => filterItems(items, query), [items, query]);
  const groups = useMemo(() => groupItems(shown), [shown]);
  const checked = countOn(statuses, items);
  // Apply resets the groups expanded on the canvas when "Hide destinations with no grants" changes; the draft shows it.
  const denv = useMemo<PickerEnv>(() => (draft.hideEmpty !== value.hideEmpty ? { ...env, tools: { ...env.tools, expanded: [] } } : env), [env, draft.hideEmpty, value.hideEmpty]);
  const ds = useMemo(() => (open ? pickerStatus(denv, draft) : statuses), [open, denv, draft, statuses]);
  const dirty = open && !samePicker(draft, base.current);
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  // changed elsewhere while open (a canvas click, auto-select, Show on map): merged in, the rows changed here kept
  useEffect(() => {
    if (!open || value === base.current) return;
    setDraft((d) => rebaseDraft(base.current, d, value));
    base.current = value;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  const show = () => {
    base.current = value;
    setNudge(false);
    setDraft(value);
    setQuery("");
    setOnly(null);
    setOpen(true);
  };
  const close = (focusButton = true) => {
    setOpen(false);
    if (focusButton) requestAnimationFrame(() => btn.current?.focus({ preventScroll: true }));
  };
  const apply = (d: PickerState = draft, focus: string | null = only) => {
    onApply(d, focus);
    close();
  };
  useEffect(() => {
    if (!open) return;
    requestAnimationFrame(() => filter.current?.focus({ preventScroll: true }));
    // A click outside closes it when nothing is pending; with pending changes it stays open and asks for Apply or
    // Cancel (a click away used to drop them silently). The canvas never closes it: clicking agents there selects them.
    const down = (e: PointerEvent) => {
      const t = e.target as Element;
      if (!wrap.current || wrap.current.contains(t) || t.closest?.(".pmap-canvas")) return;
      if (dirtyRef.current) setNudge(true);
      else close(false);
    };
    document.addEventListener("pointerdown", down);
    return () => document.removeEventListener("pointerdown", down);
  }, [open]);

  const boxes = () => [...(list.current?.querySelectorAll<HTMLInputElement>("input[type=checkbox]") ?? [])];
  const move = (from: Element | null, by: number) => {
    const bs = boxes();
    if (!bs.length) return;
    const i = from ? bs.indexOf(from as HTMLInputElement) : -1;
    const next = bs[Math.max(0, Math.min(bs.length - 1, i < 0 ? (by > 0 ? 0 : bs.length - 1) : i + by))];
    next.focus();
    next.scrollIntoView({ block: "nearest" });
  };
  const onKey = (e: ReactKeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      close();
    }
  };
  const onListKey = (e: ReactKeyboardEvent) => {
    const t = e.target as HTMLElement;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      move(t.closest(".pmap-pick-row, .pmap-pick-head")?.querySelector("input[type=checkbox]") ?? null, e.key === "ArrowDown" ? 1 : -1);
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      const bs = boxes();
      (e.key === "Home" ? bs[0] : bs[bs.length - 1])?.focus();
    } else if (e.key === "Enter" && t.tagName === "INPUT") {
      e.preventDefault();
      apply();
    }
  };
  const onFilterKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      move(null, 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const single = query.trim() && shown.length === 1 ? shown[0].id : null;
      apply(enterInFilter(denv, draft, items, query), single ?? only);
    }
  };
  const quick = (k: "hideEmpty" | "googleApis", v: boolean) => setDraft((d) => setQuick(denv, d, k, v));
  const draftChecked = countOn(ds, items);

  return (
    <div className="pmap-picker-wrap" ref={wrap} onKeyDown={onKey}>
      <Tip tip="Choose the objects on the map. Checking an agent also selects it, so its lines are drawn." placement="bottom">
        <button
          type="button"
          ref={btn}
          className={`btn btn-small btn-tonal pmap-picker-btn ${open ? "on" : ""}`}
          aria-haspopup="dialog"
          aria-expanded={open}
          aria-controls={open ? `${id}-pop` : undefined}
          onClick={() => (open ? close() : show())}
        >
          Objects: {checked} of {items.length}
          <ChevronIcon size={16} className="pmap-picker-chev" />
        </button>
      </Tip>
      {open && (
        <div className="pmap-picker" id={`${id}-pop`} role="dialog" aria-label="Objects on the map">
          <div className="pmap-picker-quick">
            <label className="pmap-check plain">
              <input type="checkbox" checked={draft.hideEmpty} onChange={(e) => quick("hideEmpty", e.target.checked)} />
              Hide destinations with no grants
            </label>
            {google && (
              <label className="pmap-check plain" title="Endpoints on *.googleapis.com. Off: one collapsed “Google APIs” node with their lines merged per agent.">
                <input type="checkbox" checked={draft.googleApis} onChange={(e) => quick("googleApis", e.target.checked)} />
                Show Google API endpoints
              </label>
            )}
          </div>
          <div className="pmap-search">
            <SearchIcon size={15} />
            <input
              ref={filter}
              type="search"
              value={query}
              placeholder="Filter by name, id or URL"
              aria-label="Filter objects by name, id or URL"
              aria-describedby={`${id}-count`}
              onChange={(e) => {
                setQuery(e.target.value);
                setOnly(null);
              }}
              onKeyDown={onFilterKey}
            />
          </div>
          <div className="pmap-picker-bar">
            <span className="small muted" id={`${id}-count`} role="status">
              {query.trim() ? `${plural(shown.length, "match", "matches")}${shown.length === 1 ? ": Enter shows only it" : ""}` : `${draftChecked} of ${items.length} checked`}
            </span>
            <button type="button" className="link-btn" onClick={() => setDraft((d) => setItems(denv, d, shown, true))} disabled={!shown.length}>
              Select all
            </button>
            <button type="button" className="link-btn" onClick={() => setDraft((d) => setItems(denv, d, shown, false))} disabled={!shown.length}>
              Clear
            </button>
          </div>
          <div className="pmap-picker-list" ref={list} role="group" aria-label="Objects: checked ones are on the map" onKeyDown={onListKey}>
            {groups.map((g) => {
              const st = checkState(ds, g.items);
              // a destination type's group checkbox is the type filter (the toolbar's type box), unless the text
              // filter narrows the rows: then it checks or unchecks the rows shown
              const typeBox = google && !query.trim();
              return (
                <div key={g.group} role="group" aria-labelledby={`${id}-${g.group}`} className="pmap-pick-group">
                  <div className="pmap-pick-head">
                    <label>
                      <input
                        type="checkbox"
                        checked={st === "all"}
                        ref={(el) => {
                          if (el) el.indeterminate = st === "some";
                        }}
                        onChange={() => setDraft((d) => (typeBox && isTypeGroup(g.group) ? toggleTypes(denv, d, [g.group], ds) : setItems(denv, d, g.items, st !== "all")))}
                      />
                      <span id={`${id}-${g.group}`}>{g.label}</span>
                    </label>
                    <span className="small muted">
                      {countOn(ds, g.items)} of {g.items.length}
                    </span>
                  </div>
                  {g.items.map((i) => {
                    const rs = ds.get(i.id);
                    const on = !!rs?.on;
                    const sel = draft.selected.includes(i.id);
                    const why = rs?.manual ? `manual override (${HIDDEN_LABEL[rs.manual].replace(/^hidden: /, "")})` : rs?.hidden ? [HIDDEN_LABEL[rs.hidden], rs.faded ? "drawn faded for a selected agent's line" : ""].filter(Boolean).join(" · ") : "";
                    return (
                      <div key={i.id} className={`pmap-pick-row ${on ? "on" : ""}`}>
                        <label title={why ? `${i.id} (${why})` : i.id}>
                          <input
                            type="checkbox"
                            checked={on}
                            aria-describedby={why ? `${id}-why-${i.id}` : undefined}
                            onChange={() => {
                              setDraft((d) => toggleItem(denv, d, i, ds));
                              setOnly(null);
                            }}
                          />
                          <span className="pmap-pick-name">{i.label}</span>
                          {why ? (
                            <span className={`pmap-pick-why ${rs?.manual ? "manual" : ""}`} id={`${id}-why-${i.id}`}>
                              {why}
                            </span>
                          ) : (
                            i.sub && <span className="pmap-pick-sub">{i.sub}</span>
                          )}
                        </label>
                        {i.source && on && (
                          <button
                            type="button"
                            className={`pmap-pick-lines ${sel ? "on" : ""}`}
                            aria-pressed={sel}
                            aria-label={`Lines of ${i.label}`}
                            title={sel ? "Its lines are drawn: click to hide them (it stays on the map)" : "Draw its lines"}
                            onClick={() => setDraft((d) => toggleSelected(d, i.id))}
                          >
                            Lines
                          </button>
                        )}
                        <button
                          type="button"
                          className="pmap-pick-only"
                          aria-label={`Only ${i.label}`}
                          onClick={() => {
                            setDraft((d) => onlyThis(denv, d, items, i.id));
                            setOnly(i.id);
                          }}
                        >
                          Only this
                        </button>
                      </div>
                    );
                  })}
                </div>
              );
            })}
            {!groups.length && <p className="small muted pmap-pick-empty">No object matches “{query.trim()}”.</p>}
          </div>
          <div className="pmap-picker-foot">
            {dirty && (
              <span className={`small pmap-picker-pending ${nudge ? "nudge" : ""}`} role="status">
                {nudge ? "Apply or Cancel your changes" : "Not applied yet"}
              </span>
            )}
            <button type="button" className="btn btn-small btn-text" onClick={() => close()}>
              Cancel
            </button>
            <button type="button" className="btn btn-small btn-primary" onClick={() => apply()}>
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
