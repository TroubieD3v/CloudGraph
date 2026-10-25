import { CircleHelp, Info } from "lucide-react";
import type { Analysis, Source } from "../types";
import { SourceLink, nameMap } from "./common";

export function Unknowns({ a, onOpen }: { a: Analysis; onOpen: (s: Source) => void }) {
  const names = nameMap(a);
  return (
    <div>
      <span className="kicker neutral">Not enough information</span>
      <h1 className="display">{a.unknowns.length} unknown</h1>
      <p className="lede">
        Unknown means the input does not contain enough information. CloudGraph reports it instead of inventing a connection between
        resources, and never walks an unknown edge when it searches for paths.
      </p>
      <div className="banner" style={{ marginTop: 24 }}>
        <Info size={18} />
        <span>Typical causes: a Service or Secret defined in another repository, a NetworkPolicy peer given as an IP block, or a Terraform value only known after apply.</span>
      </div>
      {a.unknowns.length === 0 && <div className="card empty" style={{ marginTop: 20 }}>Nothing is unknown: every reference could be resolved.</div>}
      <div className="grid cols-2" style={{ marginTop: 20 }}>
        {a.unknowns.map((u) => (
          <div key={u.id} className="card finding" data-testid="unknown">
            <div className="row between">
              <span className="tile">
                <CircleHelp size={22} />
              </span>
              <span className="chip unknown">Unknown</span>
            </div>
            <p className="msg">{u.message}</p>
            <div className="finding-actions finding-fix">
              <SourceLink src={u.source} onOpen={onOpen} />
              {u.resourceId && <span className="note">{names.get(u.resourceId)?.name ?? u.resourceId}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
