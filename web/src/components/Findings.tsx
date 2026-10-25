import { useMemo, useState } from "react";
import { Search, Sparkles } from "lucide-react";
import type { Analysis, Severity, Source } from "../types";
import { Badge, SEVERITIES, SourceLink, kindIcon, nameMap } from "./common";

const tileFor: Record<Severity, string> = { critical: "red", high: "amber", medium: "amber", low: "", info: "" };

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

  const fixable = a.findings.filter((f) => f.fix).length;

  return (
    <div>
      <span className="kicker neutral">41 rules · Compose, Kubernetes, Terraform</span>
      <h1 className="display">{a.findings.length} findings</h1>
      <p className="lede">
        Each finding points to the exact line of configuration. <b>{fixable}</b> of them can be applied virtually in the what-if simulator.
      </p>
      <div className="toolbar">
        {SEVERITIES.map((s) => (
          <button key={s} className="pill" aria-pressed={sev.has(s)} onClick={() => toggle(s)}>
            {s} {a.summary.bySeverity[s] ?? 0}
          </button>
        ))}
        <span className="search">
          <Search size={17} />
          <input type="search" placeholder="Filter by rule, resource or file…" value={q} onChange={(e) => setQ(e.target.value)} />
        </span>
        <span className="note">{shown.length} shown</span>
      </div>
      {shown.length === 0 && <div className="card empty">No findings match.</div>}
      <div className="grid cols-2">
        {shown.map((f) => {
          const r = names.get(f.resourceId);
          const Icon = kindIcon(r?.kind, r?.domain);
          return (
            <article key={f.id} className="card finding" data-testid="finding">
              <div className="row between" style={{ alignItems: "flex-start" }}>
                <span className={`tile ${tileFor[f.severity]}`}>
                  <Icon size={22} />
                </span>
                <Badge sev={f.severity} />
              </div>
              <div>
                <span className="rule">{f.ruleId}</span>
                <h4>{f.title}</h4>
              </div>
              <p className="msg">{f.message}</p>
              <div className="finding-fix">
                <div>Fix: {f.remediation}</div>
                <div className="finding-actions" style={{ marginTop: 10 }}>
                  <SourceLink src={f.source} onOpen={onOpen} />
                  <span className="note">{r?.name}</span>
                  {f.fix && (
                    <span className="chip confirmed">
                      <Sparkles size={12} /> virtual fix available
                    </span>
                  )}
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}
