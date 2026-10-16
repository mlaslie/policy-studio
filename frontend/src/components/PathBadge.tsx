// "Seen in traffic" path label for a destination (lib/paths.ts): "Private (seen in traffic)" with a lock, "Public
// (seen in traffic)" or "Mixed paths", the counts, window and last seen time in its tooltip. Nothing when no call was
// seen (or the traffic isn't read yet).
import type { PathCounts } from "../api/types";
import { pathLabel } from "../lib/paths";
import { Badge } from "./ui";
import { LockIcon } from "./Icons";

export function PathBadge({ path, window }: { path: (PathCounts & { hosts?: string[] }) | null | undefined; window: string }) {
  const l = pathLabel(path, window);
  if (!l) return null;
  return (
    <span data-testid="path-badge" data-path={l.kind}>
      <Badge tone={l.tone} title={l.tip}>
        {l.kind === "private" && <LockIcon size={11} />}
        {l.text}
      </Badge>
    </span>
  );
}
