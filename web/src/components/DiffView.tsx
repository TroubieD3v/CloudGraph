import { useEffect, useState } from "react";
import { GitCompareArrows } from "lucide-react";
import { api } from "../api";
import type { DiffResult, HistoryItem } from "../types";
import { Badge } from "./common";

const METRICS: [string, string][] = [
  ["resources", "Resources"],
  ["edges", "Relations"],
  ["findings", "Findings"],
  ["paths", "Paths"],
  ["unknowns", "Unknown"],
];

// Metrics where a lower number is better.
const LOWER_IS_BETTER = new Set(["findings", "paths", "unknowns"]);

export function DiffView({ history, refresh }: { history: HistoryItem[]; refresh: () => Promise<void> }) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!a && history.length > 1) setA(history[1].id);
    if (!b && history.length > 0) setB(history[0].id);
  }, [history, a, b]);

  const run = async (x: string, y: string) => {
    setBusy(true);
    setErr("");
    try {
      setDiff(await api.diff(x, y));
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const quick = async () => {
    setBusy(true);
    setErr("");
    try {
      const v = await api.analyzeDemo("vulnerable-all");
      const h = await api.analyzeDemo("hardened-infrastructure");
      await refresh();
      setA(v.id);
      setB(h.id);
      setDiff(await api.diff(v.id, h.id));
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const label = (h: HistoryItem) => `${h.name} · ${h.summary.paths} paths · ${new Date(h.createdAt).toLocaleTimeString()}`;

  return (
    <div>
      <span className="kicker neutral">Infrastructure diff</span>
      <h1 className="display">Before and after</h1>
      <p className="lede">
        Compare two states by what actually changed: relationships, findings and attack paths that <b>disappeared</b> or <em>appeared</em>, not
        just the counts.
      </p>
      <div className="toolbar">
        <select value={a} onChange={(e) => setA(e.target.value)} aria-label="Before state">
          <option value="">Before…</option>
          {history.map((h) => (
            <option key={h.id} value={h.id}>
              {label(h)}
            </option>
          ))}
        </select>
        <select value={b} onChange={(e) => setB(e.target.value)} aria-label="After state">
          <option value="">After…</option>
          {history.map((h) => (
            <option key={h.id} value={h.id}>
              {label(h)}
            </option>
          ))}
        </select>
        <button className="btn primary" disabled={!a || !b || busy} onClick={() => run(a, b)}>
          Compare
        </button>
        <button className="btn outlined" disabled={busy} onClick={quick}>
          <GitCompareArrows size={16} /> Compare vulnerable vs hardened demo
        </button>
      </div>
      {err && <div className="error">{err}</div>}
      {!diff && <div className="card empty">Pick two analyses to see which relationships and risk paths appeared or disappeared.</div>}
      {diff && (
        <div data-testid="diff-result" className="stack">
          <div className="card">
            <div className="row between wrap">
              <div>
                <h3 style={{ fontSize: 20 }}>Change by metric</h3>
                <p className="note" style={{ margin: "2px 0 0" }}>
                  {diff.aName} → {diff.bName}
                </p>
              </div>
              <div className="legend-row">
                <span>
                  <i style={{ background: "var(--surface-3)" }} /> Before
                </span>
                <span>
                  <i style={{ background: "var(--secondary)" }} /> After (better)
                </span>
                <span>
                  <i style={{ background: "var(--sev-critical)" }} /> After (worse)
                </span>
              </div>
            </div>
            <div className="chart" style={{ marginTop: 18 }}>
              {METRICS.map(([k, name]) => {
                const [x, y] = diff.counts[k];
                const top = Math.max(x, y, 1);
                const worse = LOWER_IS_BETTER.has(k) ? y > x : false;
                return (
                  <div className="col" key={k}>
                    <div className="num">
                      {x} → {y}
                    </div>
                    <div className="bars">
                      <i style={{ height: `${(x / top) * 100}%` }} title={`before: ${x}`} />
                      <i className={`after ${worse ? "worse" : ""}`} style={{ height: `${(y / top) * 100}%` }} title={`after: ${y}`} />
                    </div>
                    <div className="lbl">{name}</div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="grid cols-2">
            <div className="card" data-testid="diff-paths">
              <h3 style={{ fontSize: 18 }}>Risk paths</h3>
              <ul className="plain" style={{ marginTop: 10 }}>
                {diff.pathsDisappeared.map((p) => (
                  <li key={p.signature}>
                    <span className="minus">−</span>
                    <Badge sev={p.severity} /> {p.title}
                  </li>
                ))}
                {diff.pathsAppeared.map((p) => (
                  <li key={p.signature}>
                    <span className="plus">+</span>
                    <Badge sev={p.severity} /> {p.title}
                  </li>
                ))}
                {diff.pathsAppeared.length + diff.pathsDisappeared.length === 0 && <li className="note">No difference in risk paths.</li>}
              </ul>
            </div>
            <div className="card">
              <h3 style={{ fontSize: 18 }}>Findings</h3>
              <p className="note" style={{ margin: "2px 0 8px" }}>
                {diff.findingsRemoved.length} fixed · {diff.findingsAdded.length} introduced
              </p>
              <ul className="plain">
                {diff.findingsAdded.map((f) => (
                  <li key={f.id}>
                    <span className="plus">+</span>
                    <Badge sev={f.severity} /> <span className="mono note">{f.ruleId}</span> {f.title}
                  </li>
                ))}
                {diff.findingsRemoved.slice(0, 30).map((f) => (
                  <li key={f.id}>
                    <span className="minus">−</span>
                    <Badge sev={f.severity} /> <span className="mono note">{f.ruleId}</span> {f.title}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="card">
            <h3 style={{ fontSize: 18 }}>Relationships</h3>
            <p className="note" style={{ margin: "2px 0 8px" }}>
              {diff.edgesRemoved.length} removed · {diff.edgesAdded.length} added
            </p>
            <ul className="plain">
              {diff.edgesAdded.slice(0, 30).map((e) => (
                <li key={e.id}>
                  <span className="plus">+</span>
                  {e.label}
                </li>
              ))}
              {diff.edgesRemoved.slice(0, 30).map((e) => (
                <li key={e.id}>
                  <span className="minus">−</span>
                  {e.label}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
