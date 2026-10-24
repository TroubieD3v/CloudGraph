import { useEffect, useState } from "react";
import { api } from "../api";
import type { DiffResult, HistoryItem } from "../types";
import { Badge } from "./common";

const METRICS: [string, string][] = [
  ["resources", "Resources"],
  ["edges", "Relationships"],
  ["findings", "Findings"],
  ["paths", "Risk paths"],
  ["unknowns", "Unknown"],
];

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
      <div className="toolbar">
        <label className="note">
          Before{" "}
          <select value={a} onChange={(e) => setA(e.target.value)} aria-label="Before state">
            <option value="">—</option>
            {history.map((h) => (
              <option key={h.id} value={h.id}>
                {label(h)}
              </option>
            ))}
          </select>
        </label>
        <label className="note">
          After{" "}
          <select value={b} onChange={(e) => setB(e.target.value)} aria-label="After state">
            <option value="">—</option>
            {history.map((h) => (
              <option key={h.id} value={h.id}>
                {label(h)}
              </option>
            ))}
          </select>
        </label>
        <button className="btn primary" disabled={!a || !b || busy} onClick={() => run(a, b)}>
          Compare
        </button>
        <button className="btn" disabled={busy} onClick={quick}>
          Compare vulnerable vs hardened demo
        </button>
      </div>
      {err && <div className="error">{err}</div>}
      {!diff && <div className="card empty">Pick two analyses to see which relationships and risk paths appeared or disappeared.</div>}
      {diff && (
        <div data-testid="diff-result">
          <div className="diffgrid">
            {METRICS.map(([k, name]) => {
              const [x, y] = diff.counts[k];
              const cls = y < x ? "better" : y > x ? "worse" : "";
              return (
                <div className="diffcell" key={k}>
                  <div className="note">{name}</div>
                  <div className="nums">
                    {x} → <span className={`to ${k === "resources" || k === "edges" ? "" : cls}`}>{y}</span>
                  </div>
                </div>
              );
            })}
          </div>

          <h2 className="section">Risk paths</h2>
          <div className="card">
            <ul className="plain">
              {diff.pathsDisappeared.map((p) => (
                <li key={p.signature}>
                  <span className="minus">− </span>
                  <Badge sev={p.severity} /> {p.title}
                </li>
              ))}
              {diff.pathsAppeared.map((p) => (
                <li key={p.signature}>
                  <span className="plus">+ </span>
                  <Badge sev={p.severity} /> {p.title}
                </li>
              ))}
              {diff.pathsAppeared.length + diff.pathsDisappeared.length === 0 && <li className="note">No difference in risk paths.</li>}
            </ul>
          </div>

          <h2 className="section">Findings</h2>
          <div className="card">
            <div className="note">
              {diff.findingsRemoved.length} fixed · {diff.findingsAdded.length} introduced
            </div>
            <ul className="plain">
              {diff.findingsAdded.map((f) => (
                <li key={f.id}>
                  <span className="plus">+ </span>
                  <Badge sev={f.severity} /> {f.ruleId} {f.message}
                </li>
              ))}
              {diff.findingsRemoved.slice(0, 40).map((f) => (
                <li key={f.id}>
                  <span className="minus">− </span>
                  <Badge sev={f.severity} /> {f.ruleId} {f.message}
                </li>
              ))}
            </ul>
          </div>

          <h2 className="section">Relationships</h2>
          <div className="card">
            <div className="note">
              {diff.edgesRemoved.length} removed · {diff.edgesAdded.length} added
            </div>
            <ul className="plain">
              {diff.edgesAdded.slice(0, 30).map((e) => (
                <li key={e.id}>
                  <span className="plus">+ </span>
                  {e.label}
                </li>
              ))}
              {diff.edgesRemoved.slice(0, 30).map((e) => (
                <li key={e.id}>
                  <span className="minus">− </span>
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
