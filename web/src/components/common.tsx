import type { ComponentType } from "react";
import {
  Boxes,
  Cloud,
  Container,
  Database,
  Globe,
  KeyRound,
  Lock,
  Network,
  Route,
  Server,
  Shield,
  ShieldAlert,
  UserRound,
  type LucideProps,
} from "lucide-react";
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
  return (
    <span className={`chip ${c}`}>
      <span className="dot" />
      {CONF_TEXT[c]}
    </span>
  );
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

/** Icon that represents a resource kind or input domain. */
export function kindIcon(kind?: string, domain?: string): ComponentType<LucideProps> {
  switch (kind) {
    case "Internet":
      return Globe;
    case "Workload":
      return domain === "compose" ? Container : Boxes;
    case "Instance":
      return Server;
    case "Database":
      return Database;
    case "ServiceAccount":
    case "Identity":
      return UserRound;
    case "Binding":
    case "Role":
    case "Policy":
      return KeyRound;
    case "Secret":
      return Lock;
    case "Capability":
    case "Host":
      return ShieldAlert;
    case "Ingress":
    case "Service":
    case "Firewall":
      return Network;
    case "Bucket":
      return Cloud;
  }
  switch (domain) {
    case "compose":
      return Container;
    case "kubernetes":
      return Boxes;
    case "terraform":
      return Cloud;
  }
  return Shield;
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: () => void; label: string }) {
  return (
    <span className="switch">
      <input type="checkbox" role="switch" checked={checked} onChange={onChange} aria-label={label} />
      <span />
    </span>
  );
}

/** Two concentric rings with a value in the middle, as on the dashboard dial. */
export function Dial({
  outer,
  inner,
  outerColor,
  innerColor,
  children,
}: {
  outer: number;
  inner: number;
  outerColor: string;
  innerColor: string;
  children: React.ReactNode;
}) {
  const ring = (r: number, width: number, value: number, color: string) => {
    const c = 2 * Math.PI * r;
    return (
      <>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--surface-3)" strokeWidth={width} />
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={width}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - Math.max(0, Math.min(1, value)))}
        />
      </>
    );
  };
  return (
    <div className="dial">
      <div className="halo" />
      <svg viewBox="0 0 100 100">{ring(46, 5, outer, outerColor)}</svg>
      <svg viewBox="0 0 100 100" style={{ inset: "16%" }}>
        {ring(44, 7, inner, innerColor)}
      </svg>
      <div className="center">{children}</div>
    </div>
  );
}

export function PathCard({
  path,
  onOpen,
  names,
  onSelect,
  featured,
  compact,
}: {
  path: Path;
  onOpen: (s: Source) => void;
  names?: Map<string, Resource>;
  onSelect?: (id: string) => void;
  featured?: boolean;
  /** Compact cards show the chain as a one-line route and fold the details away. */
  compact?: boolean;
}) {
  const target = names?.get(path.target);
  const TargetIcon = kindIcon(target?.kind, target?.domain);
  const details = (
    <>
      <ol className="steps">
          {path.steps.map((s, i) => (
            <li key={s.edgeId + i}>
              <span className="n">{i + 1}</span>
              <span className="label">
                {s.label}
                {s.evidence && <span className="note">{s.evidence}</span>}
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
    </>
  );
  return (
    <article className={`card path ${featured ? "featured glow amber" : ""} ${compact ? "compact" : ""}`} data-testid="path-card">
      <div className="path-head">
        <div className={`tile ${path.severity === "critical" ? "red" : "amber"}`}>
          <TargetIcon size={22} />
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="row wrap" style={{ gap: 6 }}>
            <Badge sev={path.severity} />
            <Conf c={path.confidence} />
            <span className="chip">Static analysis</span>
          </div>
          <h3 className="title">{path.title}</h3>
        </div>
        <div className="score" title="Risk score: target impact × confidence">
          <b>{path.score}</b>
          <span>risk</span>
        </div>
      </div>
      {compact ? (
        <>
          <div className="route">
            {path.nodes.slice(1).map((id, i) => (
              <span key={id + i}>
                {i > 0 && <span className="sep">→</span>}
                {names?.get(id)?.name ?? id}
              </span>
            ))}
          </div>
          <details className="more">
            <summary>
              {path.steps.length} steps · {path.prerequisites.length} preconditions
            </summary>
            {details}
          </details>
        </>
      ) : (
        details
      )}
      <div className="path-foot">
        <span className="note">
          Hypothetical chain{target ? ` to ${target.name}` : ""}. Connections do not prove that exploitation is possible.
        </span>
        {onSelect && (
          <button className="btn small secondary" onClick={() => onSelect(path.id)}>
            <Route size={15} /> Show in graph
          </button>
        )}
      </div>
    </article>
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
