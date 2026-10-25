import { CircleHelp, Download, FlaskConical, Info, Lightbulb, ShieldAlert, ShieldCheck, Trash2, TriangleAlert, Waypoints } from "lucide-react";
import type { Tab } from "../App";
import type { Analysis, Coverage, Source } from "../types";
import { Dial, PathCard, SEVERITIES, nameMap } from "./common";

function posture(a: Analysis): { label: string; cls: string } {
  if (a.paths.length === 0) return { label: "Hardened", cls: "green" };
  if (a.paths.some((p) => p.severity === "critical")) return { label: "Critical", cls: "red" };
  if (a.paths.some((p) => p.severity === "high")) return { label: "At risk", cls: "amber" };
  return { label: "Watch", cls: "amber" };
}

function counts(m?: Record<string, number>) {
  const e = Object.entries(m ?? {}).sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
  return e.length ? e.map(([k, n]) => `${k} ×${n}`).join(", ") : "none";
}

function CoverageInfo({ c }: { c: Coverage }) {
  return (
    <details className="coverage" data-testid="coverage">
      <summary>What this search covered</summary>
      <dl>
        <dt>Resources</dt>
        <dd>{counts(c.resourceKinds)}</dd>
        <dt>Relationships followed</dt>
        <dd>{counts(c.edgeTypes)}</dd>
        <dt>Undecided, never followed</dt>
        <dd>{c.unknownEdges}</dd>
        <dt>Not modelled (input only)</dt>
        <dd data-testid="coverage-unmodelled">{counts(c.unmodelledTypes)}</dd>
      </dl>
    </details>
  );
}

export function Overview({
  a,
  onOpen,
  onShowPath,
  onDelete,
  onNavigate,
  alternatives,
  onToggleAlternatives,
}: {
  alternatives: boolean;
  onToggleAlternatives: (on: boolean) => void;
  a: Analysis;
  onOpen: (s: Source) => void;
  onShowPath: (id: string) => void;
  onDelete: () => void;
  onNavigate: (t: Tab) => void;
}) {
  const names = nameMap(a);
  const s = a.summary;
  const real = a.resources.filter((r) => !r.generated);
  const onPath = new Set(a.paths.flatMap((p) => p.nodes).filter((id) => names.get(id) && !names.get(id)!.generated));
  const exposure = real.length ? onPath.size / real.length : 0;
  const fixable = a.findings.length ? a.findings.filter((f) => f.fix).length / a.findings.length : 1;
  const critical = a.paths.filter((p) => p.severity === "critical").length;
  const severeTargets = a.paths.filter((p) => {
    const t = names.get(p.target);
    return t?.kind === "Host" || (t?.kind === "Capability" && !t.namespace);
  }).length;
  const pos = posture(a);
  const sev = SEVERITIES.filter((k) => s.bySeverity[k]).map((k) => `${s.bySeverity[k]} ${k}`).join(" · ");
  const hot = a.hotspots[0];
  const hotName = hot ? names.get(hot.resourceId) : undefined;

  return (
    <div>
      <section className="grid cols-12">
        <div className="card raised glow span-7">
          <div className="row between wrap">
            <span className={`kicker ${a.paths.length ? "amber" : ""}`}>
              {a.paths.length ? "Static analysis · conditional risk" : "Static analysis · no paths"}
            </span>
            <div className="row" style={{ gap: 6 }} data-testid="exports">
              {(["html", "sarif", "json"] as const).map((ext) => (
                <a key={ext} className="btn small secondary" href={`/api/analyses/${a.id}/report/${ext}`} download title={`Download ${ext.toUpperCase()} report`}>
                  <Download size={14} />
                  {ext.toUpperCase()}
                </a>
              ))}
              <button className="btn small ghost" onClick={onDelete} title="Remove from local history">
                <Trash2 size={14} />
                Delete
              </button>
            </div>
          </div>
          <h1 className="display">
            {a.paths.length} potential attack {a.paths.length === 1 ? "path" : "paths"}
          </h1>
          <p className="lede">
            {a.paths.length ? (
              <>
                CloudGraph traced <b>{a.paths.length} chains</b> through {real.length} resources of <span className="mono">{a.name}</span>.{" "}
                {severeTargets > 0 ? (
                  <>
                    <em>{severeTargets}</em> of them end at a host or a cluster-wide permission.
                  </>
                ) : (
                  "None of them reaches the host or cluster-wide permissions."
                )}
              </>
            ) : (
              <>
                No Internet-reachable route leads to a sensitive target in <span className="mono">{a.name}</span>. Findings and unknowns below still
                deserve a look.
              </>
            )}
          </p>
          <div className="actions">
            <button className="btn primary" onClick={() => onNavigate("graph")}>
              <Waypoints size={16} /> Open graph
            </button>
            <button className="btn secondary" onClick={() => onNavigate("whatif")}>
              <FlaskConical size={16} /> Simulate fixes
            </button>
          </div>
          <p className="note" style={{ marginTop: 16 }}>
            {a.inputs.length} file(s) · analysed {new Date(a.createdAt).toLocaleString()}
          </p>
        </div>

        <div className="card dial-card span-5">
          <Dial outer={exposure} inner={fixable} outerColor="var(--tertiary)" innerColor="var(--secondary)">
            <div className="big">{a.paths.length}</div>
            <div className="cap">Risk paths</div>
            {critical > 0 && (
              <div className="sub">
                <ShieldAlert size={15} /> {critical} critical
              </div>
            )}
          </Dial>
          <div className="dial-legend">
            <div>
              <div className="overline">Exposure</div>
              <div className="v amber">{Math.round(exposure * 100)}%</div>
              <div className="note">resources on a path</div>
            </div>
            <div>
              <div className="overline">Posture</div>
              <div className={`v ${pos.cls === "green" ? "green" : ""}`} style={pos.cls === "red" ? { color: "var(--sev-critical)" } : undefined}>
                {pos.cls === "green" ? <ShieldCheck size={20} /> : <TriangleAlert size={20} />}
                {pos.label}
              </div>
              <div className="note">{Math.round(fixable * 100)}% of findings fixable</div>
            </div>
          </div>
        </div>
      </section>

      <div className="stats">
        <div className="stat" data-testid="stat-resources">
          <div className="label">Resources</div>
          <div className="value">{s.resources}</div>
          <div className="sub">{s.edges} relationships</div>
        </div>
        <div className="stat" data-testid="stat-findings">
          <div className="label">Findings</div>
          <div className="value">{s.findings}</div>
          <div className="sub">{sev || "none"}</div>
        </div>
        <div className="stat amber" data-testid="stat-paths">
          <div className="label">Risk paths</div>
          <div className="value">{s.paths}</div>
          <div className="sub">conditional, static analysis</div>
        </div>
        <div className="stat" data-testid="stat-unknown">
          <div className="label">Unknown</div>
          <div className="value">{s.unknowns}</div>
          <div className="sub">not enough information</div>
        </div>
      </div>

      <div className="section-head">
        <div>
          <h2>Potential attack paths</h2>
          {a.pathSearch && (
            <p data-testid="search-limits">
              Search limits: depth {a.pathSearch.limits.maxDepth} edges · {a.pathSearch.limits.maxPivots} network pivot(s) per path ·{" "}
              {a.pathSearch.candidates} of max {a.pathSearch.limits.maxCandidates} candidates ·{" "}
              {a.pathSearch.searchComplete ? "search complete" : "search incomplete"} ·{" "}
              {a.pathSearch.scopeLimited ? "limited coverage" : "no routes excluded"}
            </p>
          )}
        </div>
        <label className="toggle" title="List the routes that were merged into each path, with their preconditions">
          <input type="checkbox" data-testid="alt-toggle" checked={alternatives} onChange={(e) => onToggleAlternatives(e.target.checked)} />
          Show alternative paths
        </label>
      </div>
      <div className="banner" style={{ marginBottom: 16 }}>
        <Info size={18} />
        <span>
          A path shows how separate weaknesses could be chained; it does not prove the exposed application can actually be compromised. Every
          step lists its source and the conditions it relies on.
        </span>
      </div>
      {a.pathSearch?.notices?.map((n) =>
        n.startsWith("Incomplete") ? (
          <div key={n} className="error" role="alert" data-testid="search-incomplete">
            <TriangleAlert size={18} />
            {n}
          </div>
        ) : (
          <p key={n} className="note" data-testid="search-scope" style={{ margin: "0 0 16px" }}>
            {n}
          </p>
        ),
      )}
      {a.pathSearch?.coverage && <CoverageInfo c={a.pathSearch.coverage} />}
      {a.paths.length === 0 && <div className="card empty">No attack paths found in this configuration.</div>}
      {a.paths.length > 0 && <PathCard path={a.paths[0]} onOpen={onOpen} names={names} onSelect={onShowPath} featured />}
      {a.paths.length > 1 && (
        <div className="grid cols-2" style={{ marginTop: 16 }}>
          {a.paths.slice(1).map((p) => (
            <PathCard key={p.id} path={p} onOpen={onOpen} names={names} onSelect={onShowPath} compact />
          ))}
        </div>
      )}

      <section className="grid cols-12" style={{ marginTop: 32 }}>
        <div className="card span-8" style={{ background: "var(--surface-2)" }}>
          <div className="row" style={{ alignItems: "flex-start", gap: 18 }}>
            <span className="tile dark">
              <Lightbulb size={22} />
            </span>
            <div>
              <h3 style={{ fontSize: 20 }}>{hot && hotName ? `Fix ${hotName.name} first` : "Keep it this way"}</h3>
              <p className="note" style={{ fontSize: 14, marginTop: 6 }}>
                {hot && hotName
                  ? `${hotName.type} ${hotName.name} takes part in ${hot.paths} of the ${a.paths.length} paths. A single change there breaks all of them; the what-if simulator shows which one.`
                  : "No resource is shared by several paths. Compare this state with a vulnerable version in Diff to see what changed."}
              </p>
              <div className="actions" style={{ marginTop: 16 }}>
                <button className="btn primary" onClick={() => onNavigate(hot ? "whatif" : "diff")}>
                  {hot ? "Simulate the fix" : "Open diff"}
                </button>
              </div>
            </div>
          </div>
        </div>
        <div className="card inverse span-4">
          <span className="tile" style={{ background: "rgba(255,255,255,.08)", color: "var(--inverse-fg)" }}>
            <CircleHelp size={22} />
          </span>
          <h3 style={{ fontSize: 20, marginTop: 16 }}>{s.unknowns} unresolved</h3>
          <p style={{ fontSize: 13.5 }}>References the input could not resolve. They are reported, never guessed.</p>
          <button className="btn small outlined" style={{ color: "var(--inverse-fg)", borderColor: "rgba(255,255,255,.25)", marginTop: 8 }} onClick={() => onNavigate("unknown")}>
            Review unknowns
          </button>
        </div>
      </section>

      {a.hotspots.length > 0 && (
        <>
          <div className="section-head">
            <div>
              <h2>Shared choke points</h2>
              <p>Fixing one of these resources breaks several chains at once.</p>
            </div>
          </div>
          <div className="grid cols-3">
            {a.hotspots.slice(0, 6).map((h) => {
              const r = names.get(h.resourceId);
              return (
                <div key={h.resourceId} className="card">
                  <div className="overline">{r?.type}</div>
                  <h3 style={{ fontSize: 18, marginTop: 4 }}>{r?.name ?? h.resourceId}</h3>
                  <div className="row between" style={{ marginTop: 14 }}>
                    <span className="note">in {h.paths} paths</span>
                    <span className="note">{Math.round((h.paths / a.paths.length) * 100)}%</span>
                  </div>
                  <div className="bar amber" style={{ marginTop: 6 }}>
                    <i style={{ width: `${(h.paths / a.paths.length) * 100}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}

      {a.warnings && a.warnings.length > 0 && (
        <>
          <div className="section-head">
            <div>
              <h2>Import warnings</h2>
            </div>
          </div>
          <div className="card">
            <ul className="plain">
              {a.warnings.map((w) => (
                <li key={w} className="note">
                  {w}
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  );
}
