// Small building blocks shared by the steps.
import { useState, type ReactNode } from "react";
import { useStudio } from "../store";
import { GLOSSARY } from "../lib/glossary";
import type { Loadable } from "../store";
import { ApiIcon, ChevronIcon, InfoIcon, RobotIcon, ServerIcon, WarnIcon } from "./Icons";
import type { ResourceKind } from "../api/types";

/** A glossary term: dotted underline, hover shows the short definition, click opens the Learn glossary. */
export function Term({ k, children }: { k: string; children?: ReactNode }) {
  const { showTerm } = useStudio();
  const g = GLOSSARY[k];
  if (!g) return <>{children}</>;
  return (
    <button type="button" className="term" onClick={() => showTerm(k)} aria-label={`${g.term}: ${g.short} Open in glossary`}>
      {children ?? g.term}
      <span className="term-tip" role="tooltip">
        <b>{g.term}</b>
        {g.short}
        <span className="term-more">Click for more</span>
      </span>
    </button>
  );
}

export function Badge({ tone = "neutral", children, title }: { tone?: "neutral" | "blue" | "green" | "amber" | "red" | "purple"; children: ReactNode; title?: string }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function Callout({ tone = "info", title, children, icon }: { tone?: "info" | "warn" | "danger" | "ok"; title?: ReactNode; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className={`callout callout-${tone}`} role={tone === "danger" ? "alert" : undefined}>
      <span className="callout-icon">{icon ?? (tone === "info" || tone === "ok" ? <InfoIcon size={18} /> : <WarnIcon size={18} />)}</span>
      <div>
        {title && <div className="callout-title">{title}</div>}
        {children && <div className="callout-body">{children}</div>}
      </div>
    </div>
  );
}

export function StepHeader({ title, lead, actions }: { title: string; lead: ReactNode; actions?: ReactNode }) {
  return (
    <header className="step-head">
      <div>
        <h1>{title}</h1>
        <p className="lead">{lead}</p>
      </div>
      {actions && <div className="step-actions">{actions}</div>}
    </header>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span className="spinner-wrap" role="status">
      <span className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </span>
  );
}

/** Renders loading / error / empty states for a Loadable, or the children with the data. */
export function Load<T>({ l, what, children }: { l: Loadable<T>; what: string; children: (d: T) => ReactNode }) {
  const { ctx, goto } = useStudio();
  if (!ctx.project || !ctx.region)
    return (
      <div className="empty">
        <p>Set a project and region first.</p>
        <button className="btn btn-primary" onClick={() => goto(0)}>
          Go to Context
        </button>
      </div>
    );
  if (l.error && !l.data)
    return (
      <Callout tone="danger" title={`Couldn't load ${what}`}>
        <span className="mono small">{l.error}</span>
      </Callout>
    );
  if (!l.data)
    return (
      <div className="skeleton-wrap">
        <Spinner label={`Reading ${what}…`} />
        <div className="skeleton" />
        <div className="skeleton short" />
      </div>
    );
  return <>{children(l.data)}</>;
}

export function Disclosure({ summary, children, defaultOpen = false }: { summary: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`disclosure ${open ? "open" : ""}`}>
      <button type="button" className="disclosure-btn" aria-expanded={open} onClick={() => setOpen(!open)}>
        <ChevronIcon size={16} className="chev" />
        {summary}
      </button>
      {open && <div className="disclosure-body">{children}</div>}
    </div>
  );
}

export function KindIcon({ kind, size = 16 }: { kind: ResourceKind | "registry" | "engine"; size?: number }) {
  if (kind === "mcp_server") return <ServerIcon size={size} />;
  if (kind === "endpoint" || kind === "registry") return <ApiIcon size={size} />;
  return <RobotIcon size={size} />;
}

export function Tabs<T extends string>({ value, onChange, items, label }: { value: T; onChange: (v: T) => void; items: { id: T; label: ReactNode; count?: number }[]; label: string }) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {items.map((it) => (
        <button key={it.id} role="tab" aria-selected={value === it.id} className={`tab ${value === it.id ? "active" : ""}`} onClick={() => onChange(it.id)}>
          {it.label}
          {it.count != null && <span className="tab-count">{it.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <code className="mono-chip" title={title}>
      {children}
    </code>
  );
}
