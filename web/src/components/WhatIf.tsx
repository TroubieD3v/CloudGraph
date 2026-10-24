import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Analysis, Fix, Simulation } from "../types";
import { Badge, downloadText } from "./common";

interface Impact {
  paths: number;
  findings: number;
}

export function WhatIf({ a }: { a: Analysis }) {
  const [impact, setImpact] = useState<Record<string, Impact>>({});
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [sim, setSim] = useState<Simulation | null>(null);
  const [patch, setPatch] = useState<{ patch: string; manual: string[] } | null>(null);
  const [err, setErr] = useState("");

  // Per-fix impact: simulate every fix on its own once.
  useEffect(() => {
    let live = true;
    setImpact({});
    setChosen(new Set());
    setSim(null);
    setPatch(null);
    (async () => {
      const out: Record<string, Impact> = {};
      await Promise.all(
        a.fixes.map(async (f) => {
          try {
            const r = await api.simulate(a.id, [f.id]);
            out[f.id] = { paths: r.pathsResolved.length, findings: r.findingsResolved.length };
          } catch {
            out[f.id] = { paths: 0, findings: 0 };
          }
        }),
      );
      if (live) setImpact(out);
    })();
    return () => {
      live = false;
    };
  }, [a]);

  const ids = useMemo(() => [...chosen].sort(), [chosen]);
  useEffect(() => {
    setPatch(null);
    if (ids.length === 0) {
      setSim(null);
      return;
    }
    let live = true;
    const t = setTimeout(() => {
      api
        .simulate(a.id, ids)
        .then((r) => live && (setSim(r), setErr("")))
        .catch((e) => live && setErr(String(e.message ?? e)));
    }, 120);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [a.id, ids]);

  const sorted = useMemo(() => {
    const score = (f: Fix) => (impact[f.id]?.paths ?? 0) * 100 + (impact[f.id]?.findings ?? 0);
    return [...a.fixes].sort((x, y) => score(y) - score(x) || x.description.localeCompare(y.description));
  }, [a.fixes, impact]);

  const toggle = (id: string) => {
    const n = new Set(chosen);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setChosen(n);
  };

  const sevOf = (fixId: string) => a.findings.find((f) => f.fix?.id === fixId)?.severity;

  const exportPatch = async () => {
    try {
      setPatch(await api.patch(a.id, ids));
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };

  if (a.fixes.length === 0) return <div className="card empty">No virtual fixes are available for this configuration.</div>;

  return (
    <div className="whatif">
      <div>
        <div className="toolbar">
          <h2 className="section" style={{ margin: 0 }}>
            Simulate fix
          </h2>
          <span className="spacer" style={{ flex: 1 }} />
          <button className="btn small" onClick={() => setChosen(new Set(a.fixes.map((f) => f.id)))}>
            Select all
          </button>
          <button className="btn small" onClick={() => setChosen(new Set())}>
            Clear
          </button>
        </div>
        <div className="note" style={{ marginBottom: 10 }}>
          Fixes are applied to a virtual copy of the configuration. Your files are never changed.
        </div>
        {sorted.map((f) => {
          const im = impact[f.id];
          const sev = sevOf(f.id);
          return (
            <label key={f.id} className={`fix ${chosen.has(f.id) ? "on" : ""}`} data-testid="fix">
              <input type="checkbox" checked={chosen.has(f.id)} onChange={() => toggle(f.id)} aria-label={f.description} />
              <span>
                {sev && <Badge sev={sev} />} {f.description}
                <div className="note">
                  resolves {f.findingIds?.length ?? 0} finding(s) ·{" "}
                  {f.edits?.length ? (
                    <span>patch: {[...new Set(f.edits.map((e) => e.file))].join(", ")}</span>
                  ) : (
                    <span>manual change{f.action.startsWith("tf_") ? " in Terraform" : ""}</span>
                  )}
                </div>
              </span>
              <span className="impact">{im ? <><b>{im.paths}</b> path{im.paths === 1 ? "" : "s"}</> : "…"}</span>
            </label>
          );
        })}
      </div>

      <div className="result">
        <div className="card" data-testid="sim-result">
          <div className="note">Potential paths</div>
          <div className="bignum">
            <span>{a.paths.length}</span>
            <span className="arrow">→</span>
            <span className={sim && sim.pathsAfter < a.paths.length ? "good" : undefined} data-testid="paths-after">
              {sim ? sim.pathsAfter : a.paths.length}
            </span>
            <span className="note" style={{ fontWeight: 400, fontSize: 13 }}>
              resolved {sim ? sim.pathsResolved.length : 0}
            </span>
          </div>
          <div className="note">
            Findings {a.findings.length} → {sim ? sim.findingsAfter : a.findings.length}
          </div>
          {err && <div className="error">{err}</div>}
          {!sim && <p className="note">Tick one or more fixes to recompute the graph.</p>}
          {sim && (
            <>
              <ul className="plain" style={{ marginTop: 10 }}>
                {sim.pathsResolved.map((p) => (
                  <li key={p.signature} className="resolved">
                    ✓ {p.title}
                  </li>
                ))}
                {sim.pathsRemaining.map((p) => (
                  <li key={p.signature} className="remaining">
                    • still reachable: {p.title}
                  </li>
                ))}
                {sim.pathsNew.map((p) => (
                  <li key={p.signature} style={{ color: "var(--crit)" }}>
                    ! new: {p.title}
                  </li>
                ))}
              </ul>
              {sim.skipped && sim.skipped.length > 0 && <p className="note">Skipped: {sim.skipped.join("; ")}</p>}
              <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                <button className="btn primary" onClick={exportPatch}>
                  Export patch
                </button>
              </div>
            </>
          )}
        </div>
        {patch && (
          <div className="card" data-testid="patch">
            <div className="toolbar">
              <b>Proposed patch</b>
              <span style={{ flex: 1 }} />
              <button className="btn small" onClick={() => downloadText("cloudgraph-fixes.patch", patch.patch)}>
                Download
              </button>
            </div>
            <div className="note">Review before applying: git apply --unidiff-zero cloudgraph-fixes.patch</div>
            <pre className="patch">{patch.patch}</pre>
            {patch.manual?.length > 0 && (
              <>
                <div className="note">Manual steps (no mechanical edit possible):</div>
                <ul className="plain">
                  {patch.manual.map((m) => (
                    <li key={m} className="note">
                      {m}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
