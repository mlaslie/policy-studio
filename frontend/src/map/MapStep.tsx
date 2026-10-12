// Policy map step (lazy-loaded chunk): who can reach what, drawn from the policy state Policy Studio already reads
// (docs/VISUALIZATION_PLAN.md). Phase 0 is the shell: the step, its place in the stepper and the full-width layout.
import { StepHeader } from "../components/ui";
import { useStudio } from "../store";

export default function MapStep() {
  const { goto } = useStudio();
  return (
    <>
      <StepHeader
        title="Policy map"
        lead={
          <>
            Who can reach what: your agents, the gateways their traffic goes through, and the destinations they're allowed to call. Every line comes from a grant in your project; nothing changes until you
            stage it and apply.
          </>
        }
      />
      <div className="card empty-card map-placeholder">
        <h3>The policy map is being built…</h3>
        <p>Until it's ready, the next steps show the same information as lists: gateways, Model Armor, the Agent Registry inventory and the audit of current grants.</p>
        <div className="row center-row">
          <button className="btn btn-primary" onClick={() => goto("gateways")}>
            See your gateways
          </button>
          <button className="btn btn-tonal" onClick={() => goto("audit")}>
            Open the audit
          </button>
        </div>
      </div>
    </>
  );
}
