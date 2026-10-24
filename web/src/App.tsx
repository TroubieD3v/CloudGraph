import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { Analysis, Demo, HistoryItem, Source } from "./types";
import { DiffView } from "./components/DiffView";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Findings } from "./components/Findings";
import { GraphView } from "./components/GraphView";
import { Overview } from "./components/Overview";
import { SourceViewer } from "./components/SourceViewer";
import { WhatIf } from "./components/WhatIf";

type Tab = "overview" | "graph" | "findings" | "whatif" | "diff" | "unknown";

const ACCEPT = ".yaml,.yml,.json";

async function readFiles(list: FileList | File[]): Promise<{ name: string; content: string }[]> {
  const out: { name: string; content: string }[] = [];
  for (const f of Array.from(list)) {
    if (!/\.(ya?ml|json)$/i.test(f.name)) continue;
    const rel = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
    out.push({ name: rel.split("/").slice(rel.includes("/") ? 1 : 0).join("/") || f.name, content: await f.text() });
  }
  return out;
}

export default function App() {
  const [demos, setDemos] = useState<Demo[]>([]);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [a, setA] = useState<Analysis | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [pathId, setPathId] = useState("");
  const [src, setSrc] = useState<Source | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [over, setOver] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => setHistory(await api.history()), []);

  useEffect(() => {
    api.demos().then(setDemos).catch((e) => setErr(String(e.message)));
    refresh().catch(() => undefined);
  }, [refresh]);

  const adopt = useCallback(
    async (p: Promise<Analysis>) => {
      setBusy(true);
      setErr("");
      try {
        const next = await p;
        setA(next);
        setPathId("");
        setTab("overview");
        await refresh();
      } catch (e) {
        setErr(String((e as Error).message));
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  const onFiles = async (files: FileList | File[]) => {
    const read = await readFiles(files);
    if (read.length === 0) {
      setErr("No .yaml, .yml or .json files found in the selection.");
      return;
    }
    await adopt(api.analyzeFiles("upload", read));
  };

  const removeCurrent = async () => {
    if (!a || !window.confirm(`Delete analysis "${a.name}" from the local history?`)) return;
    try {
      await api.remove(a.id);
      setA(null);
      await refresh();
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };

  const showPath = (id: string) => {
    setPathId(id);
    setTab("graph");
  };

  if (!a) {
    return (
      <div className="app">
        <Header history={history} current={undefined} onPick={(id) => adopt(api.get(id))} onUpload={() => fileInput.current?.click()} />
        <div className="content">
          <div className="welcome">
            <h1>Infrastructure Attack Path Analysis</h1>
            <p className="note">
              Import Docker Compose, Kubernetes YAML or a Terraform plan (<code>terraform show -json</code>). CloudGraph builds a resource graph
              locally, explains how weaknesses chain together, and never connects to your cloud account.
            </p>
            {err && <div className="error">{err}</div>}
            <h2 className="section">Try a demo project</h2>
            {demos
              .filter((d) => d.name !== "vulnerable-all")
              .map((d) => (
                <button key={d.name} className="demo-card" disabled={busy} onClick={() => adopt(api.analyzeDemo(d.name))} data-testid={`demo-${d.name}`}>
                  <b>{d.title}</b>
                  <span className="note">{d.description}</span>
                </button>
              ))}
            <h2 className="section">Or analyse your own files</h2>
            <div
              className={`dropzone ${over ? "over" : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                setOver(true);
              }}
              onDragLeave={() => setOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setOver(false);
                void onFiles(e.dataTransfer.files);
              }}
            >
              Drop YAML / JSON files here or{" "}
              <button className="btn small" onClick={() => fileInput.current?.click()}>
                choose files
              </button>
            </div>
          </div>
        </div>
        <input ref={fileInput} type="file" accept={ACCEPT} multiple hidden onChange={(e) => e.target.files && void onFiles(e.target.files)} data-testid="file-input" />
      </div>
    );
  }

  const tabs: [Tab, string, number?][] = [
    ["overview", "Overview", a.paths.length],
    ["graph", "Graph"],
    ["findings", "Findings", a.findings.length],
    ["whatif", "What-if"],
    ["diff", "Diff"],
    ["unknown", "Unknown", a.unknowns.length],
  ];

  return (
    <div className="app">
      <Header history={history} current={a} onPick={(id) => adopt(api.get(id))} onUpload={() => fileInput.current?.click()} demos={demos} onDemo={(n) => adopt(api.analyzeDemo(n))} busy={busy} />
      <nav className="tabs" role="tablist">
        {tabs.map(([id, label, count]) => (
          <button key={id} role="tab" aria-selected={tab === id} className="tab" onClick={() => setTab(id)}>
            {label}
            {count !== undefined && <span className="count">{count}</span>}
          </button>
        ))}
      </nav>
      <div className={`content ${tab === "graph" ? "full" : ""}`}>
        {err && <div className="error">{err}</div>}
        <ErrorBoundary resetKey={`${a.id}:${tab}`}>
          {tab === "overview" && <Overview a={a} onOpen={setSrc} onShowPath={showPath} onDelete={removeCurrent} />}
          {tab === "graph" && <GraphView a={a} pathId={pathId} setPathId={setPathId} onOpen={setSrc} />}
          {tab === "findings" && <Findings a={a} onOpen={setSrc} />}
          {tab === "whatif" && <WhatIf a={a} />}
          {tab === "diff" && <DiffView history={history} refresh={refresh} />}
          {tab === "unknown" && <Unknowns a={a} onOpen={setSrc} />}
        </ErrorBoundary>
      </div>
      {src && <SourceViewer src={src} lines={a.sources?.[src.file]} onClose={() => setSrc(null)} />}
      <input ref={fileInput} type="file" accept={ACCEPT} multiple hidden onChange={(e) => e.target.files && void onFiles(e.target.files)} data-testid="file-input" />
    </div>
  );
}

function Header({
  history,
  current,
  onPick,
  onUpload,
  demos,
  onDemo,
  busy,
}: {
  history: HistoryItem[];
  current?: Analysis;
  onPick: (id: string) => void;
  onUpload: () => void;
  demos?: Demo[];
  onDemo?: (name: string) => void;
  busy?: boolean;
}) {
  return (
    <header className="topbar">
      <div className="brand">
        <b>CloudGraph</b>
        <span>Infrastructure Security Intelligence</span>
      </div>
      <div className="spacer" />
      <div className="picker">
        {busy && <span className="note">analysing…</span>}
        {history.length > 0 && (
          <select value={current?.id ?? ""} onChange={(e) => e.target.value && onPick(e.target.value)} aria-label="Analysis history">
            {!current && <option value="">History…</option>}
            {history.map((h) => (
              <option key={h.id} value={h.id}>
                {h.name} · {h.summary.paths} paths
              </option>
            ))}
          </select>
        )}
        {demos && onDemo && (
          <select value="" onChange={(e) => e.target.value && onDemo(e.target.value)} aria-label="Analyse demo">
            <option value="">Analyse demo…</option>
            {demos.map((d) => (
              <option key={d.name} value={d.name}>
                {d.title}
              </option>
            ))}
          </select>
        )}
        <button className="btn" onClick={onUpload}>
          Upload files
        </button>
      </div>
    </header>
  );
}

function Unknowns({ a, onOpen }: { a: Analysis; onOpen: (s: Source) => void }) {
  return (
    <div>
      <div className="banner">
        Unknown means the input does not contain enough information. CloudGraph reports it instead of inventing a connection between resources.
      </div>
      {a.unknowns.length === 0 && <div className="card empty">Nothing is unknown: every reference could be resolved.</div>}
      {a.unknowns.map((u) => (
        <div key={u.id} className="card" data-testid="unknown">
          <span className="chip unknown">Unknown</span> {u.message}
          <div style={{ marginTop: 4 }}>
            {u.source.file && (
              <button className="srcbtn" onClick={() => onOpen(u.source)}>
                {u.source.file}
                {u.source.line ? `:${u.source.line}` : ""}
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
