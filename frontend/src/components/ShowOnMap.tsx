// "Show on map": opens the policy map (step 1) focused on a node or a line, with the direction set from it.
import type { MapFocus } from "../map/focus";
import { useStudio } from "../store";
import { MapIcon } from "./Icons";
import { Tip } from "./Tooltip";

export function ShowOnMap({ focus, what, compact, onOpen }: { focus: MapFocus | null; what: string; compact?: boolean; onOpen?: () => void }) {
  const { openMap } = useStudio();
  if (!focus) return null;
  const go = () => {
    openMap(focus);
    onOpen?.();
  };
  return (
    <Tip tip={`Open the policy map focused on ${what}.`}>
      {compact ? (
        <button type="button" className="icon-btn" aria-label={`Show ${what} on the map`} onClick={go}>
          <MapIcon size={14} />
        </button>
      ) : (
        <button type="button" className="btn btn-small btn-text" onClick={go}>
          <MapIcon size={14} /> Show on map
        </button>
      )}
    </Tip>
  );
}
