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
:root{color-scheme:dark;--bg:#0d0e10;--card:#16181c;--card2:#1d2025;--line:#262a31;--fg:#f2f4f7;--mut:#a7b3c6;--dim:#8291a8;--acc:#ff8f2f;--ok:#53bc74;--crit:#ff5a50;--high:#ff8f2f;--med:#ffb87a;--low:#262a31;--lowfg:#f2f4f7;--info:#1d2025}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 Inter,system-ui,Segoe UI,sans-serif}
main{max-width:1040px;margin:0 auto;padding:40px 24px}
h1{font:700 40px/1.05 Manrope,system-ui,sans-serif;letter-spacing:-.04em;margin:10px 0 8px}
h2{font:700 22px Manrope,system-ui,sans-serif;letter-spacing:-.02em;margin:40px 0 14px}
.kicker{display:inline-block;padding:3px 12px;border-radius:999px;background:color-mix(in srgb,var(--acc) 15%,transparent);color:var(--acc);font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}.stat{background:var(--card);border-radius:16px;padding:16px 18px}
.stat b{display:block;font:700 30px Manrope,system-ui,sans-serif}.stat span{color:var(--dim);font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
.card{background:var(--card);border-radius:20px;padding:20px 22px;margin:14px 0}
.badge{display:inline-block;padding:2px 8px;font-size:11px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#170b00}
.critical{background:var(--crit);color:#fff}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low);color:var(--lowfg)}.info{background:var(--info);color:var(--lowfg)}
code{font-family:ui-monospace,Consolas,monospace;color:var(--acc)}ol{margin:12px 0 0 20px;padding:0}li{margin:5px 0}
.note{color:var(--dim);font-size:12.5px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px;border-top:1px solid var(--line);vertical-align:top}th{color:var(--dim);font-size:11px;letter-spacing:.1em;text-transform:uppercase}
</style></head><body><main>
<span class="kicker">CloudGraph · static analysis</span>
<h1>{{.A.Name}}</h1>
<div class="note">Infrastructure Attack Path Analysis · generated {{.A.CreatedAt}} · static analysis of configuration only</div>
<div class="stats">
<div class="stat"><b>{{.A.Summary.Resources}}</b><span>Resources</span></div>
<div class="stat"><b>{{.A.Summary.Findings}}</b><span>Findings</span></div>
<div class="stat"><b>{{.A.Summary.Paths}}</b><span>Risk paths</span></div>
<div class="stat"><b>{{.A.Summary.Unknowns}}</b><span>Unknown</span></div></div>

{{range .A.PathSearch.Notices}}<div class="card" style="color:var(--acc)">{{.}}</div>{{end}}
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
