import { useEffect, useMemo, useState } from "react";
import { Check, CircleDot, Download, FileCode, Hand, TriangleAlert, WandSparkles } from "lucide-react";
import { api } from "../api";
import type { Analysis, Fix, Simulation } from "../types";
import { Badge, Toggle, downloadText } from "./common";

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

  const header = (
    <>
      <span className="kicker">Virtual copy · files never change</span>
      <h1 className="display">What-if simulator</h1>
      <p className="lede">
        Switch fixes on to apply them to a virtual copy of the configuration. CloudGraph recomputes the whole graph and shows which attack
        paths <b>disappear</b>, then exports the change as a patch for review.
      </p>
    </>
  );

  if (a.fixes.length === 0)
    return (
      <div>
        {header}
        <div className="card empty" style={{ marginTop: 24 }}>
          No virtual fixes are available for this configuration.
        </div>
      </div>
    );

  const resolvedShare = sim && sim.pathsBefore ? sim.pathsResolved.length / sim.pathsBefore : 0;

  return (
    <div>
      {header}
      <div className="whatif">
        <div>
          <div className="row between" style={{ marginBottom: 14 }}>
            <span className="overline">{a.fixes.length} fixes · sorted by impact</span>
            <div className="row" style={{ gap: 6 }}>
              <button className="btn small secondary" onClick={() => setChosen(new Set(a.fixes.map((f) => f.id)))}>
                Select all
              </button>
              <button className="btn small ghost" onClick={() => setChosen(new Set())}>
                Clear
              </button>
            </div>
          </div>
          {sorted.map((f) => {
            const im = impact[f.id];
            const sev = sevOf(f.id);
            const on = chosen.has(f.id);
            return (
              <div key={f.id} className={`fix ${on ? "on" : ""}`} data-testid="fix">
                <span className={`tile ${f.edits?.length ? "green" : "amber"}`}>{f.edits?.length ? <FileCode size={20} /> : <Hand size={20} />}</span>
                <div style={{ minWidth: 0 }}>
                  <div className="desc">{f.description}</div>
                  <div className="note">
                    {sev && <Badge sev={sev} />}
                    <span>resolves {f.findingIds?.length ?? 0} finding(s) ·</span>
                    {f.edits?.length ? (
                      <span>patch: {[...new Set(f.edits.map((e) => e.file))].join(", ")}</span>
                    ) : (
                      <span>manual change{f.action.startsWith("tf_") ? " in Terraform" : ""}</span>
                    )}
                  </div>
                </div>
                <div className="side">
                  <div className="impact">
                    <b className={im && im.paths === 0 ? "zero" : undefined}>{im ? im.paths : "…"}</b>
                    <span>{im?.paths === 1 ? "path" : "paths"}</span>
                  </div>
                  <Toggle checked={on} onChange={() => toggle(f.id)} label={f.description} />
                </div>
              </div>
            );
          })}
        </div>

        <div className="result stack">
          <div className="card inverse" data-testid="sim-result">
            <div className="row between">
              <span className="overline" style={{ color: "var(--inverse-muted)" }}>
                Potential paths
              </span>
              <WandSparkles size={18} />
            </div>
            <div className="bignum">
              <span>{a.paths.length}</span>
              <span className="arrow">→</span>
              <span className={sim && sim.pathsAfter < a.paths.length ? "good" : undefined} data-testid="paths-after">
                {sim ? sim.pathsAfter : a.paths.length}
              </span>
            </div>
            <div className="row between" style={{ fontSize: 13 }}>
              <span>resolved {sim ? sim.pathsResolved.length : 0}</span>
              <span>
                findings {a.findings.length} → {sim ? sim.findingsAfter : a.findings.length}
              </span>
            </div>
            <div className="bar green" style={{ marginTop: 10, background: "rgba(255,255,255,.1)" }}>
              <i style={{ width: `${resolvedShare * 100}%`, background: "#53bc74" }} />
            </div>
            {err && <div className="error">{err}</div>}
            {!sim && <p style={{ marginTop: 16 }}>Switch on one or more fixes to recompute the graph.</p>}
            {sim && (
              <>
                <ul className="resolved-list">
                  {sim.pathsResolved.map((p) => (
                    <li key={p.signature} className="ok">
                      <Check size={16} /> {p.title}
                    </li>
                  ))}
                  {sim.pathsRemaining.map((p) => (
                    <li key={p.signature} className="left">
                      <CircleDot size={16} /> still reachable: {p.title}
                    </li>
                  ))}
                  {sim.pathsNew.map((p) => (
                    <li key={p.signature} className="new">
                      <TriangleAlert size={16} /> new: {p.title}
                    </li>
                  ))}
                </ul>
                {sim.skipped && sim.skipped.length > 0 && <p className="note">Skipped: {sim.skipped.join("; ")}</p>}
                <div className="actions">
                  <button className="btn green" onClick={exportPatch}>
                    Export patch
                  </button>
                </div>
              </>
            )}
          </div>
          {patch && (
            <div className="card" data-testid="patch">
              <div className="row between">
                <h3 style={{ fontSize: 18 }}>Proposed patch</h3>
                <button className="btn small secondary" onClick={() => downloadText("cloudgraph-fixes.patch", patch.patch)}>
                  <Download size={14} /> Download
                </button>
              </div>
              <p className="note" style={{ marginTop: 6 }}>
                Review before applying: <code>git apply --unidiff-zero cloudgraph-fixes.patch</code>
              </p>
              <pre className="patch">{patch.patch}</pre>
              {patch.manual?.length > 0 && (
                <>
                  <div className="overline" style={{ marginTop: 16 }}>
                    Manual steps (no mechanical edit possible)
                  </div>
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
    </div>
  );
}
