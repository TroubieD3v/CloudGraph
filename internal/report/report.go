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
	fmt.Fprintf(w, "Search: %s\n", SearchStatus(a.PathSearch))
	for _, n := range a.PathSearch.Notices {
		fmt.Fprintf(w, "! %s\n", n)
	}
	fmt.Fprintln(w)

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
			switch {
			case len(p.Alternatives) > 0:
				fmt.Fprintf(w, "       alternative routes (%d of %d merged):\n", len(p.Alternatives), p.SimilarRoutes)
				for _, alt := range p.Alternatives {
					fmt.Fprintf(w, "         - %s\n", routeLabel(alt))
					for _, c := range alt.Prerequisites {
						fmt.Fprintf(w, "             needs: %s\n", c)
					}
				}
			case p.SimilarRoutes > 0:
				fmt.Fprintf(w, "       +%d similar route(s) merged into this one; --alternatives lists them\n", p.SimilarRoutes)
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
	"upper":  strings.ToUpper,
	"route":  routeLabel,
	"status": SearchStatus,
	"join":   strings.Join,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CloudGraph report — {{.A.Name}}</title>
<style>
:root{color-scheme:dark;--bg:#191b1e;--card:#1f2226;--card2:#24272c;--line:#2f333a;--fg:#d5d7da;--mut:#a3a8ae;--dim:#8d939a;--acc:#8fb4d8;--warn:#d0a866;--ok:#94b08e;--crit:#d98577;--high:#d0a866;--med:#c9b07f;--low:#9ba8b5;--lowfg:#d5d7da;--info:#6b7178}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 'IBM Plex Sans',system-ui,'Segoe UI',sans-serif;font-feature-settings:"tnum"}
main{max-width:1080px;margin:0 auto;padding:28px 24px}
h1{font-weight:600;font-size:20px;line-height:1.2;margin:8px 0 4px}
h2{font-weight:600;font-size:14px;margin:28px 0 8px}
.kicker{display:inline-block;padding:0 6px;line-height:18px;border:1px solid var(--line);color:var(--dim);font-size:11px;font-weight:500}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;margin:16px 0;background:var(--line);border:1px solid var(--line)}.stat{background:var(--card);padding:8px 12px}
.stat b{display:block;font:500 20px 'IBM Plex Mono',ui-monospace,Consolas,monospace}.stat span{color:var(--dim);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);padding:12px 14px;margin:8px 0}
.badge{display:inline-block;padding:0 6px;line-height:18px;font-size:11px;font-weight:500;border:1px solid var(--line);color:var(--dim)}
.critical{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 45%,transparent);background:color-mix(in srgb,var(--crit) 12%,transparent)}.high{color:var(--high);border-color:color-mix(in srgb,var(--high) 45%,transparent);background:color-mix(in srgb,var(--high) 12%,transparent)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}
code{font-family:'IBM Plex Mono',ui-monospace,Consolas,monospace;font-size:12px;color:var(--acc)}ol{margin:8px 0 0 20px;padding:0}li{margin:3px 0}
.note{color:var(--dim);font-size:12px}table{width:100%;border-collapse:collapse;border:1px solid var(--line);background:var(--card)}td,th{text-align:left;padding:5px 8px;border-top:1px solid var(--line);vertical-align:top}th{color:var(--dim);font-size:12px;font-weight:500;background:var(--card2)}
</style></head><body><main>
<span class="kicker">CloudGraph · static analysis</span>
<h1>{{.A.Name}}</h1>
<div class="note">Search: {{status .A.PathSearch}}</div>
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
{{if .Prerequisites}}<div class="note" style="margin-top:8px">Preconditions: {{join .Prerequisites "; "}}</div>{{end}}
{{if .Alternatives}}<details style="margin-top:8px"><summary class="note">Alternative routes ({{len .Alternatives}} of {{.SimilarRoutes}} merged)</summary><ul>{{range .Alternatives}}<li>{{route .}}{{if .Prerequisites}}<div class="note">Preconditions: {{join .Prerequisites "; "}}</div>{{end}}</li>{{end}}</ul></details>
{{else if .SimilarRoutes}}<div class="note" style="margin-top:8px">+{{.SimilarRoutes}} similar route(s) merged into this one.</div>{{end}}</div>
{{else}}<div class="card note">No attack paths found.</div>{{end}}

<h2>Findings</h2>
<div class="card"><table><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Detail</th></tr>
{{range .A.Findings}}<tr><td><span class="badge {{.Severity}}">{{upper .Severity}}</span></td><td>{{.RuleID}}</td><td><code>{{loc .Src}}</code></td><td>{{.Message}}<div class="note">Fix: {{.Remediation}}</div></td></tr>{{end}}
</table></div>

{{if .A.Unknowns}}<h2>Unknown — not enough information</h2>
<div class="card"><ul>{{range .A.Unknowns}}<li>{{.Message}} <code>{{loc .Src}}</code></li>{{end}}</ul></div>{{end}}
</main></body></html>`))

// SearchStatus is the one-line answer to "did this search cover everything?".
func SearchStatus(s model.PathSearch) string {
	search := "complete"
	if !s.SearchComplete {
		search = "INCOMPLETE (a limit stopped it)"
	}
	scope := "no routes excluded by limits"
	if s.ScopeLimited {
		scope = "LIMITED COVERAGE (some routes excluded by limits)"
	}
	return fmt.Sprintf("%s; %s", search, scope)
}

// routeLabel names a route by the resources it passes through.
func routeLabel(p *model.Path) string {
	return strings.Join(p.Nodes[1:], " → ") + " (" + string(p.Confidence) + ")"
}

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
