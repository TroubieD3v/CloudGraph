import type { Analysis, Source } from "../types";
import { PathCard, SEVERITIES, nameMap } from "./common";

export function Overview({
  a,
  onOpen,
  onShowPath,
  onDelete,
}: {
  a: Analysis;
  onOpen: (s: Source) => void;
  onShowPath: (id: string) => void;
  onDelete: () => void;
}) {
  const names = nameMap(a);
  const s = a.summary;
  const sev = SEVERITIES.filter((k) => s.bySeverity[k]).map((k) => `${s.bySeverity[k]} ${k}`).join(" · ");
  return (
    <div>
      <div className="toolbar" style={{ justifyContent: "space-between" }}>
        <div>
          <b>{a.name}</b>{" "}
          <span className="note">
            {a.inputs.length} file(s) · analysed {new Date(a.createdAt).toLocaleString()}
          </span>
        </div>
        <div style={{ display: "flex", gap: 6 }} data-testid="exports">
          {(["html", "sarif", "json"] as const).map((ext) => (
            <a key={ext} className="btn small" href={`/api/analyses/${a.id}/report/${ext}`} download>
              {ext.toUpperCase()}
            </a>
          ))}
          <button className="btn small ghost" onClick={onDelete} title="Remove from local history">
            Delete
          </button>
        </div>
      </div>
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
        <div className="stat risk" data-testid="stat-paths">
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

      <div className="banner">
        CloudGraph analyses configuration offline. A path shows how separate weaknesses could be chained; it does not prove the exposed
        application can actually be compromised. Every step lists its source and the conditions it relies on.
      </div>

      <h2 className="section">Potential attack paths</h2>
      {a.pathSearch?.notices?.map((n) =>
        n.startsWith("Incomplete") ? (
          <div key={n} className="error" role="alert" data-testid="search-incomplete">
            {n}
          </div>
        ) : (
          <p key={n} className="note" data-testid="search-scope">
            {n}
          </p>
        ),
      )}
      {a.pathSearch && (
        <p className="note" data-testid="search-limits">
          Search limits: depth {a.pathSearch.limits.maxDepth} edges · {a.pathSearch.limits.maxPivots} network pivot(s) per path ·{" "}
          {a.pathSearch.candidates} of max {a.pathSearch.limits.maxCandidates} candidates · {a.pathSearch.complete ? "complete" : "incomplete"}
        </p>
      )}
      {a.paths.length === 0 && <div className="card empty">No attack paths found in this configuration.</div>}
      {a.paths.map((p) => (
        <PathCard key={p.id} path={p} onOpen={onOpen} names={names} onSelect={onShowPath} />
      ))}

      {a.hotspots.length > 0 && (
        <>
          <h2 className="section">Shared choke points</h2>
          <div className="card">
            <div className="note" style={{ marginBottom: 6 }}>
              Fixing one of these resources breaks several chains at once.
            </div>
            <ul className="plain">
              {a.hotspots.slice(0, 6).map((h) => (
                <li key={h.resourceId}>
                  <b>{names.get(h.resourceId)?.name ?? h.resourceId}</b>{" "}
                  <span className="note">
                    {names.get(h.resourceId)?.type} · participates in {h.paths} paths
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}

      {a.warnings && a.warnings.length > 0 && (
        <>
          <h2 className="section">Import warnings</h2>
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
