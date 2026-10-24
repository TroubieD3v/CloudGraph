import { useEffect } from "react";
import type { Source } from "../types";

export function SourceViewer({
  src,
  lines,
  onClose,
}: {
  src: Source;
  lines: string[] | undefined;
  onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const line = src.line ?? 0;
  const from = Math.max(1, line - 8);
  const to = lines ? Math.min(lines.length, Math.max(line, src.endLine ?? line) + 10) : 0;
  const view = lines ? lines.slice(from - 1, to) : [];

  return (
    <div className="modal-back" onClick={onClose} role="dialog" aria-label="Configuration source">
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header>
          <span className="mono">
            {src.file}
            {line ? `:${line}` : ""}
          </span>
          {src.path && <span className="note">{src.path}</span>}
          <span className="spacer" />
          <span className="note">secrets are masked</span>
          <button className="btn small" onClick={onClose}>
            Close
          </button>
        </header>
        <div className="code" data-testid="source-code">
          {!lines && <div className="note" style={{ padding: 16 }}>Source is not available for this analysis.</div>}
          {view.map((text, i) => {
            const n = from + i;
            return (
              <div key={n} className={n === line ? "hl" : undefined}>
                <span className="ln">{n}</span>
                <span>{text || " "}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
