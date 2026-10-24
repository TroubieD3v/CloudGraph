import type { Analysis, Confidence, Path, Resource, Severity, Source } from "../types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function Badge({ sev }: { sev: Severity }) {
  return <span className={`badge ${sev}`}>{sev}</span>;
}

const CONF_TEXT: Record<Confidence, string> = {
  confirmed: "Confirmed in config",
  inferred: "Inferred",
  conditional: "Conditional",
  unknown: "Unknown",
};

export function Conf({ c }: { c: Confidence }) {
  return <span className={`chip ${c}`}>{CONF_TEXT[c]}</span>;
}

export function SourceLink({ src, onOpen }: { src: Source; onOpen: (s: Source) => void }) {
  if (!src.file) return null;
  return (
    <button className="srcbtn" onClick={() => onOpen(src)} title="Show configuration">
      {src.file}
      {src.line ? `:${src.line}` : ""}
    </button>
  );
}

export function nameMap(a: Analysis): Map<string, Resource> {
  return new Map(a.resources.map((r) => [r.id, r]));
}

export function PathCard({
  path,
  onOpen,
  names,
  onSelect,
  selected,
}: {
  path: Path;
  onOpen: (s: Source) => void;
  names?: Map<string, Resource>;
  onSelect?: (id: string) => void;
  selected?: boolean;
}) {
  return (
    <div className="card path" data-testid="path-card" style={selected ? { borderColor: "var(--accent)" } : undefined}>
      <div className="path-head">
        <Badge sev={path.severity} />
        <span className="title">{path.title}</span>
        <Conf c={path.confidence} />
        <span className="chip">Static analysis</span>
        <span className="score" title="Risk score: target impact × confidence">
          risk {path.score}
        </span>
        {onSelect && (
          <button className="btn small" onClick={() => onSelect(path.id)}>
            Show in graph
          </button>
        )}
      </div>
      <ol className="steps">
        {path.steps.map((s, i) => (
          <li key={s.edgeId + i}>
            <span className="n">{i + 1}</span>
            <span className="label">
              {s.label}
              {s.evidence && <span className="note"> — {s.evidence}</span>}
            </span>
            <span className="meta">
              <Conf c={s.confidence} />
              <SourceLink src={s.source} onOpen={onOpen} />
            </span>
          </li>
        ))}
      </ol>
      {path.prerequisites.length > 0 && (
        <div className="prereq">
          <b>Must hold for this path to work</b>
          <ul>
            {path.prerequisites.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      <div className="note" style={{ marginTop: 8 }}>
        Hypothetical chain
        {names ? ` → target: ${names.get(path.target)?.name ?? path.target}` : ""}. Connections do not prove that exploitation is possible.
      </div>
    </div>
  );
}

export function downloadText(name: string, text: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
