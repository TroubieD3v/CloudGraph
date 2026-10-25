import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  CircleHelp,
  FlaskConical,
  GitCompareArrows,
  LayoutDashboard,
  ListChecks,
  Moon,
  Sun,
  Upload,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import { api } from "./api";
import type { Analysis, Demo, HistoryItem, Source } from "./types";
import { useTheme, type Theme } from "./theme";
import { DiffView } from "./components/DiffView";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Findings } from "./components/Findings";
import { GraphView } from "./components/GraphView";
import { Overview } from "./components/Overview";
import { SourceViewer } from "./components/SourceViewer";
import { Unknowns } from "./components/Unknowns";
import { WhatIf } from "./components/WhatIf";

export type Tab = "overview" | "graph" | "findings" | "whatif" | "diff" | "unknown";

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
  const [theme, toggleTheme] = useTheme();
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

  const header = (
    <Header
      theme={theme}
      onTheme={toggleTheme}
      history={history}
      current={a ?? undefined}
      onPick={(id) => adopt(api.get(id))}
      onUpload={() => fileInput.current?.click()}
      demos={a ? demos : undefined}
      onDemo={(n) => adopt(api.analyzeDemo(n))}
      busy={busy}
      onHome={() => setA(null)}
    />
  );
  const input = (
    <input ref={fileInput} type="file" accept={ACCEPT} multiple hidden onChange={(e) => e.target.files && void onFiles(e.target.files)} data-testid="file-input" />
  );

  if (!a) {
    const shown = demos.filter((d) => d.name !== "vulnerable-all");
    return (
      <div className="app">
        {header}
        <main className="content">
          <div className="welcome">
            <span className="kicker">Offline · Static analysis</span>
            <h1 className="display">Infrastructure attack path analysis</h1>
            <p className="lede">
              Import Docker Compose, Kubernetes YAML or a Terraform plan (<code>terraform show -json</code>). CloudGraph builds a resource graph{" "}
              <b>locally</b>, explains how separate weaknesses <em>chain together</em>, and never connects to your cloud account.
            </p>
            {err && <div className="error">{err}</div>}

            <div className="section-head">
              <div>
                <h2>Try a demo project</h2>
                <p>Bundled with the binary; nothing is downloaded.</p>
              </div>
            </div>
            <div className="grid cols-3">
              {shown.map((d, i) => (
                <button
                  key={d.name}
                  className={`demo-card ${i === 0 ? "featured" : ""}`}
                  disabled={busy}
                  onClick={() => adopt(api.analyzeDemo(d.name))}
                  data-testid={`demo-${d.name}`}
                >
                  <span className={`tile ${d.name.startsWith("hardened") ? "green" : i === 0 ? "dark" : "amber"}`}>
                    {d.name.startsWith("hardened") ? <ListChecks size={22} /> : d.name.includes("kubernetes") ? <Waypoints size={22} /> : <LayoutDashboard size={22} />}
                  </span>
                  <b>{d.title}</b>
                  <span className="note">{d.description}</span>
                  <span className="go">
                    Analyse <ArrowRight size={15} />
                  </span>
                </button>
              ))}
            </div>

            <div className="section-head">
              <div>
                <h2>Or analyse your own files</h2>
                <p>YAML and JSON stay on this machine; secrets are masked before anything is stored.</p>
              </div>
            </div>
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
              <span className="tile">
                <Upload size={22} />
              </span>
              <div>Drop Compose, Kubernetes or Terraform plan files here</div>
              <button className="btn primary" onClick={() => fileInput.current?.click()}>
                Choose files
              </button>
            </div>
          </div>
        </main>
        {input}
      </div>
    );
  }

  const tabs: [Tab, string, LucideIcon, number?][] = [
    ["overview", "Overview", LayoutDashboard, a.paths.length],
    ["graph", "Graph", Waypoints],
    ["findings", "Findings", ListChecks, a.findings.length],
    ["whatif", "What-if", FlaskConical],
    ["diff", "Diff", GitCompareArrows],
    ["unknown", "Unknown", CircleHelp, a.unknowns.length],
  ];

  return (
    <div className="app">
      {header}
      <div className="navwrap">
        <nav className="navpill" role="tablist" aria-label="Views">
          {tabs.map(([id, label, Icon, count]) => (
            <button key={id} role="tab" aria-selected={tab === id} className="navitem" onClick={() => setTab(id)}>
              <Icon size={18} />
              {label}
              {count !== undefined && <span className="count">{count}</span>}
            </button>
          ))}
        </nav>
      </div>
      <main className={`content ${tab === "graph" ? "full" : ""}`}>
        {err && <div className="error">{err}</div>}
        <ErrorBoundary resetKey={`${a.id}:${tab}`}>
          {tab === "overview" && <Overview a={a} onOpen={setSrc} onShowPath={showPath} onDelete={removeCurrent} onNavigate={setTab} />}
          {tab === "graph" && <GraphView a={a} pathId={pathId} setPathId={setPathId} onOpen={setSrc} theme={theme} />}
          {tab === "findings" && <Findings a={a} onOpen={setSrc} />}
          {tab === "whatif" && <WhatIf a={a} />}
          {tab === "diff" && <DiffView history={history} refresh={refresh} />}
          {tab === "unknown" && <Unknowns a={a} onOpen={setSrc} />}
        </ErrorBoundary>
      </main>
      {src && <SourceViewer src={src} lines={a.sources?.[src.file]} onClose={() => setSrc(null)} />}
      {input}
    </div>
  );
}

function Header({
  theme,
  onTheme,
  history,
  current,
  onPick,
  onUpload,
  demos,
  onDemo,
  busy,
  onHome,
}: {
  theme: Theme;
  onTheme: () => void;
  history: HistoryItem[];
  current?: Analysis;
  onPick: (id: string) => void;
  onUpload: () => void;
  demos?: Demo[];
  onDemo: (name: string) => void;
  busy?: boolean;
  onHome: () => void;
}) {
  const next = theme === "dark" ? "light" : "dark";
  return (
    <header className="topbar">
      <a
        className="brand"
        href="/"
        onClick={(e) => {
          e.preventDefault();
          onHome();
        }}
      >
        <span className="brand-mark">
          <Waypoints size={22} />
        </span>
        <span className="brand-text">
          <b>CloudGraph</b>
          <small>Infrastructure attack paths</small>
        </span>
      </a>
      <div className="spacer" />
      <div className="controls">
        {busy && <span className="busy">analysing…</span>}
        {history.length > 0 && (
          <select className="hide-sm" value={current?.id ?? ""} onChange={(e) => e.target.value && onPick(e.target.value)} aria-label="Analysis history">
            {!current && <option value="">History…</option>}
            {history.map((h) => (
              <option key={h.id} value={h.id}>
                {h.name} · {h.summary.paths} paths
              </option>
            ))}
          </select>
        )}
        {demos && (
          <select className="hide-sm" value="" onChange={(e) => e.target.value && onDemo(e.target.value)} aria-label="Analyse demo">
            <option value="">Analyse demo…</option>
            {demos.map((d) => (
              <option key={d.name} value={d.name}>
                {d.title}
              </option>
            ))}
          </select>
        )}
        <button className="btn primary" onClick={onUpload}>
          <Upload size={16} />
          <span className="hide-sm">Upload files</span>
        </button>
        <button className="icon-btn" onClick={onTheme} aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`} data-testid="theme-toggle">
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
      </div>
    </header>
  );
}
