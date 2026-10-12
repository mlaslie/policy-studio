// Endpoint labels and Google API detection for the policy map (docs/VISUALIZATION_PLAN.md §5.4). Pure; shared by the
// graph (node labels), the canvas (card titles) and the table view.

/** The host of an http(s) URL with the port as written (`cloudtrace.mtls.googleapis.com:443`), lowercase; null when
 *  the URL has no host. An explicit port is kept even when it's the scheme's default: the platform registers
 *  `host` and `host:443` as separate entries, and dropping it would give two cards the same title. */
export function hostOf(url: string | null | undefined): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?([^/?#]+)/i.exec((url ?? "").trim());
  return m ? m[1].toLowerCase() : null;
}

/** Google API endpoints: the URL host is `*.googleapis.com` (any port). */
export function isGoogleApi(url: string | null | undefined): boolean {
  const h = hostOf(url);
  return !!h && /(^|\.)googleapis\.com(:\d+)?$/.test(h);
}

/** An endpoint's card title: the host (with its port, when the URL spells one out) when the display name is empty,
 *  equals the host, or ends with it (`acme-prod cloudtrace.googleapis.com` → `cloudtrace.googleapis.com`); the
 *  display name otherwise (a name someone chose, like "Weather API"). */
export function endpointLabel(displayName: string | null | undefined, url: string | null | undefined): string {
  const name = (displayName ?? "").trim();
  const hp = hostOf(url);
  if (!hp) return name || (url ?? "");
  if (!name) return hp;
  const host = hp.replace(/:\d+$/, "");
  const lower = name.toLowerCase();
  const endsWith = (s: string) => lower === s || lower.endsWith(` ${s}`) || lower.endsWith(`/${s}`) || lower.endsWith(`:${s}`);
  return endsWith(hp) || endsWith(host) ? hp : name;
}

/** Shorten from the middle so both ends show: `iamcredentials.mtls.googleapis.com:443` → `iamcredentials.mtls…apis.com:443`.
 *  About 60% of the room goes to the start (the distinguishing service name), the rest to the end (domain, port). */
export function middleEllipsis(s: string, max: number): string {
  if (s.length <= max || max < 5) return s;
  const keep = max - 1;
  const head = Math.ceil(keep * 0.6);
  return `${s.slice(0, head)}…${s.slice(s.length - (keep - head))}`;
}

/** Shorten a host from the middle, eliding the shared domain first so the part that tells entries apart shows:
 *  the service labels (`cloudresourcemanager.mtls`) and the port are kept, the domain keeps its end (`…apis.com`).
 *  When the service labels alone don't fit, they're shortened from their own middle too
 *  (`cloudresour…er.mtls…apis.com:443`). Labels that aren't hosts get plain middleEllipsis. */
export function shortLabel(s: string, max: number): string {
  if (s.length <= max) return s;
  const m = /^([a-z0-9-]+(?:\.[a-z0-9-]+)*?)(\.[a-z0-9-]+\.[a-z]{2,})(:\d+)?$/i.exec(s);
  if (!m) return middleEllipsis(s, max);
  const [, svc, dom, port = ""] = m;
  const minDom = Math.min(dom.length, 8);
  const room = max - 1 - port.length; // for service + domain end
  if (svc.length + minDom <= room) return `${svc}…${dom.slice(dom.length - (room - svc.length))}${port}`;
  return `${middleEllipsis(svc, room - minDom)}…${dom.slice(dom.length - minDom)}${port}`;
}

/** Characters of an endpoint's card title before it's shortened (the card is sized for about this many). */
export const TITLE_MAX = 32;
