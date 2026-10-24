package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// JSON writes the full analysis.
func JSON(w io.Writer, a *model.Analysis) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(a)
}

// Text writes a human-readable terminal report.
func Text(w io.Writer, a *model.Analysis) {
	s := a.Summary
	fmt.Fprintf(w, "CloudGraph — %s\n", a.Name)
	fmt.Fprintf(w, "Resources: %d   Edges: %d   Findings: %d   Risk paths: %d   Unknown: %d\n\n", s.Resources, s.Edges, s.Findings, s.Paths, s.Unknowns)
	for _, n := range a.PathSearch.Notices {
		fmt.Fprintf(w, "! %s\n", n)
	}
	if len(a.PathSearch.Notices) > 0 {
		fmt.Fprintln(w)
	}

	if len(a.Paths) > 0 {
		fmt.Fprintln(w, "POTENTIAL ATTACK PATHS (static analysis; not proof of exploitation)")
		for _, p := range a.Paths {
			fmt.Fprintf(w, "\n  [%s %d] %s   (%s)\n", strings.ToUpper(p.Severity), p.Score, p.Title, p.Confidence)
			for i, st := range p.Steps {
				loc := ""
				if st.Src.File != "" {
					loc = fmt.Sprintf("  [%s", st.Src.File)
					if st.Src.Line > 0 {
						loc += fmt.Sprintf(":%d", st.Src.Line)
					}
					loc += "]"
				}
				fmt.Fprintf(w, "    %d. %s%s\n", i+1, st.Label, loc)
			}
			for _, c := range p.Prerequisites {
				fmt.Fprintf(w, "       needs: %s\n", c)
			}
		}
		fmt.Fprintln(w)
	}

	if len(a.Findings) > 0 {
		fmt.Fprintln(w, "FINDINGS")
		for _, f := range a.Findings {
			loc := f.Src.File
			if f.Src.Line > 0 {
				loc += fmt.Sprintf(":%d", f.Src.Line)
			}
			fmt.Fprintf(w, "  %-8s %-11s %s\n           %s\n", strings.ToUpper(f.Severity), f.RuleID, loc, f.Message)
		}
		fmt.Fprintln(w)
	}

	if len(a.Unknowns) > 0 {
		fmt.Fprintln(w, "UNKNOWN (insufficient information; no connection assumed)")
		for _, u := range a.Unknowns {
			fmt.Fprintf(w, "  - %s\n", u.Message)
		}
		fmt.Fprintln(w)
	}
	for _, wn := range a.Warnings {
		fmt.Fprintf(w, "warning: %s\n", wn)
	}
}

type htmlData struct {
	A        *model.Analysis
	Names    map[string]string
	SevOrder []string
}

var htmlTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"loc": func(s model.Source) string {
		if s.Line > 0 {
			return fmt.Sprintf("%s:%d", s.File, s.Line)
		}
		return s.File
	},
	"upper": strings.ToUpper,
	"join":  strings.Join,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CloudGraph report — {{.A.Name}}</title>
<style>
:root{color-scheme:dark;--bg:#0f1115;--card:#171a21;--line:#262b36;--fg:#e6e8ee;--mut:#8b93a7;--crit:#ef5350;--high:#ff8a3d;--med:#e8b53c;--low:#5aa9ff;--info:#8b93a7}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.stats{display:flex;gap:12px;margin:16px 0}.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px}
.stat b{display:block;font-size:24px}.stat span{color:var(--mut);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.badge{display:inline-block;border-radius:4px;padding:1px 8px;font-size:11px;font-weight:600;color:#111}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}.info{background:var(--info)}
code{font-family:ui-monospace,Consolas,monospace;color:var(--mut)}ol{margin:8px 0 0 18px;padding:0}li{margin:3px 0}
.note{color:var(--mut);font-size:12px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}
</style></head><body><main>
<h1>CloudGraph — {{.A.Name}}</h1>
<div class="note">Infrastructure Attack Path Analysis · generated {{.A.CreatedAt}} · static analysis of configuration only</div>
<div class="stats">
<div class="stat"><b>{{.A.Summary.Resources}}</b><span>Resources</span></div>
<div class="stat"><b>{{.A.Summary.Findings}}</b><span>Findings</span></div>
<div class="stat"><b>{{.A.Summary.Paths}}</b><span>Risk paths</span></div>
<div class="stat"><b>{{.A.Summary.Unknowns}}</b><span>Unknown</span></div></div>

{{range .A.PathSearch.Notices}}<div class="card" style="border-color:#5b4420;color:#e8c88f">{{.}}</div>{{end}}
<h2>Potential attack paths</h2>
<p class="note">A path shows how separate weaknesses could be chained. It is conditional: connections do not prove that the exposed application can actually be compromised.</p>
{{range .A.Paths}}<div class="card"><span class="badge {{.Severity}}">{{upper .Severity}} {{.Score}}</span> <b>{{.Title}}</b> <span class="note">· {{.Confidence}}</span>
<ol>{{range .Steps}}<li>{{.Label}} <code>{{loc .Src}}</code> <span class="note">[{{.Confidence}}]</span></li>{{end}}</ol>
{{if .Prerequisites}}<div class="note" style="margin-top:8px">Preconditions: {{join .Prerequisites "; "}}</div>{{end}}</div>
{{else}}<div class="card note">No attack paths found.</div>{{end}}

<h2>Findings</h2>
<div class="card"><table><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Detail</th></tr>
{{range .A.Findings}}<tr><td><span class="badge {{.Severity}}">{{upper .Severity}}</span></td><td>{{.RuleID}}</td><td><code>{{loc .Src}}</code></td><td>{{.Message}}<div class="note">Fix: {{.Remediation}}</div></td></tr>{{end}}
</table></div>

{{if .A.Unknowns}}<h2>Unknown — not enough information</h2>
<div class="card"><ul>{{range .A.Unknowns}}<li>{{.Message}} <code>{{loc .Src}}</code></li>{{end}}</ul></div>{{end}}
</main></body></html>`))

// HTML writes a self-contained report.
func HTML(w io.Writer, a *model.Analysis) error {
	names := map[string]string{}
	for _, r := range a.Resources {
		names[r.ID] = r.Name
	}
	return htmlTmpl.Execute(w, htmlData{A: a, Names: names})
}

// Table of counts per severity, used by CLI summaries.
func SeverityCounts(a *model.Analysis) []string {
	var keys []string
	for k := range a.Summary.BySeverity {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return model.SeverityRank(keys[i]) > model.SeverityRank(keys[j]) })
	var out []string
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%d %s", a.Summary.BySeverity[k], k))
	}
	return out
}
