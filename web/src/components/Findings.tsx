import { useMemo, useState } from "react";
import type { Analysis, Severity, Source } from "../types";
import { Badge, SEVERITIES, SourceLink, nameMap } from "./common";

export function Findings({ a, onOpen }: { a: Analysis; onOpen: (s: Source) => void }) {
  const [sev, setSev] = useState<Set<Severity>>(new Set());
  const [q, setQ] = useState("");
  const names = useMemo(() => nameMap(a), [a]);

  const shown = a.findings.filter((f) => {
    if (sev.size && !sev.has(f.severity)) return false;
    const hay = `${f.ruleId} ${f.title} ${f.message} ${names.get(f.resourceId)?.name ?? ""} ${f.source.file}`.toLowerCase();
    return !q || hay.includes(q.toLowerCase());
  });

  const toggle = (s: Severity) => {
    const next = new Set(sev);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSev(next);
  };

  return (
    <div>
      <div className="toolbar">
        {SEVERITIES.map((s) => (
          <button key={s} className="pill" aria-pressed={sev.has(s)} onClick={() => toggle(s)}>
            {s} {a.summary.bySeverity[s] ?? 0}
          </button>
        ))}
        <input type="search" placeholder="Filter by rule, resource or file…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <span className="note">{shown.length} shown</span>
      </div>
      {shown.length === 0 && <div className="card empty">No findings match.</div>}
      {shown.map((f) => (
        <div key={f.id} className="card finding" data-testid="finding">
          <div>
            <Badge sev={f.severity} />
          </div>
          <div>
            <div>
              <span className="rule">{f.ruleId}</span> <b>{f.title}</b>
            </div>
            <div className="msg">{f.message}</div>
            <div className="fix">Fix: {f.remediation}</div>
            <div className="finding-actions">
              <SourceLink src={f.source} onOpen={onOpen} />
              <span className="note">{names.get(f.resourceId)?.name}</span>
              {f.fix && <span className="chip">virtual fix available</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
