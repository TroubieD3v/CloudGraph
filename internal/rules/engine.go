// Package rules contains the security checks. Every rule is a pure function of
// the resource inventory and graph, has a stable ID, and is tested against both
// a vulnerable and a hardened example.
package rules

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/graph"
	"github.com/TroubieD3v/cloudgraph/internal/mask"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

// Ctx is what a rule can see.
type Ctx struct {
	Inv *parse.Inventory
	G   *graph.Graph
}

// Draft is a rule hit before it is turned into a Finding.
type Draft struct {
	Key      string // distinguishes several hits of one rule on one resource
	Message  string
	Line     int
	Path     string
	Severity string // optional override
	Fix      *model.Fix
}

// Rule is one registered check.
type Rule struct {
	ID          string
	Title       string
	Severity    string
	Domain      string
	Kinds       []string // resource kinds the rule is applied to
	Remediation string
	Check       func(c *Ctx, r *model.Resource) []Draft
}

var registry []Rule

func register(r Rule) { registry = append(registry, r) }

// All returns the registered rules sorted by ID.
func All() []Rule {
	out := append([]Rule(nil), registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Run applies every rule and returns findings plus the de-duplicated fix list.
func Run(inv *parse.Inventory, g *graph.Graph) ([]*model.Finding, []*model.Fix) {
	c := &Ctx{Inv: inv, G: g}
	var findings []*model.Finding
	fixes := map[string]*model.Fix{}
	for _, rule := range All() {
		for _, r := range g.Resources {
			if r.Domain != rule.Domain || !kindMatch(rule.Kinds, r.Kind) {
				continue
			}
			for _, d := range rule.Check(c, r) {
				sev := rule.Severity
				if d.Severity != "" {
					sev = d.Severity
				}
				line := d.Line
				if line == 0 {
					line = r.Src.Line
				}
				f := &model.Finding{
					ID:          fmt.Sprintf("%s|%s|%s", rule.ID, r.ID, d.Key),
					RuleID:      rule.ID,
					Title:       rule.Title,
					Severity:    sev,
					Message:     d.Message,
					Remediation: rule.Remediation,
					ResourceID:  r.ID,
					Src:         model.Source{File: r.Src.File, Line: line, Path: d.Path},
				}
				if d.Fix != nil {
					fx := *d.Fix
					fx.ID = fixID(fx)
					if ex, ok := fixes[fx.ID]; ok {
						ex.FindingIDs = append(ex.FindingIDs, f.ID)
						fx = *ex
					} else {
						fx.FindingIDs = []string{f.ID}
						cp := fx
						fixes[fx.ID] = &cp
					}
					f.Fix = &fx
				}
				findings = append(findings, f)
			}
		}
	}
	model.SortFindings(findings)
	var fl []*model.Fix
	for _, f := range fixes {
		fl = append(fl, f)
	}
	sort.Slice(fl, func(i, j int) bool { return fl[i].ID < fl[j].ID })
	return findings, fl
}

func kindMatch(kinds []string, k string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

func fixID(f model.Fix) string {
	b, _ := json.Marshal([]any{f.Action, f.Target, f.Params})
	h := sha1.Sum(b)
	return "fix-" + hex.EncodeToString(h[:4])
}

// ---- fix builders ----------------------------------------------------------

func newFix(action, target, desc string, params map[string]any, edits ...model.Edit) *model.Fix {
	return &model.Fix{Action: action, Target: target, Description: desc, Params: params, Edits: edits}
}

func (c *Ctx) line(file string, n int) (string, bool) {
	ls := c.Inv.Files[file]
	if n < 1 || n > len(ls) {
		return "", false
	}
	return ls[n-1], true
}

var kvLine = regexp.MustCompile(`^(\s*(?:-\s+)?)([A-Za-z0-9_.\-]+)(\s*[:=]\s*)(.*)$`)

// maskLine hides secret-looking values in a line before it is stored as patch context.
func maskLine(l string) string {
	if m := kvLine.FindStringSubmatch(l); m != nil && mask.IsSecretKey(m[2]) && !mask.IsReference(strings.Trim(m[4], `"' `)) {
		return m[1] + m[2] + m[3] + mask.Redacted
	}
	v, hit := mask.EnvValue("x", l)
	if hit {
		return v
	}
	return l
}

func (c *Ctx) deleteLines(file string, from, to int) (model.Edit, bool) {
	if from < 1 || to < from {
		return model.Edit{}, false
	}
	var old []string
	for i := from; i <= to; i++ {
		l, ok := c.line(file, i)
		if !ok {
			return model.Edit{}, false
		}
		old = append(old, maskLine(l))
	}
	return model.Edit{File: file, StartLine: from, EndLine: to, Old: old}, true
}

func (c *Ctx) replaceLine(file string, n int, newText string) (model.Edit, bool) {
	l, ok := c.line(file, n)
	if !ok {
		return model.Edit{}, false
	}
	return model.Edit{File: file, StartLine: n, EndLine: n, Replace: newText, Old: []string{maskLine(l)}}, true
}

var boolVal = regexp.MustCompile(`(:\s*)("?)(true|false)("?)`)

// setBoolLine rewrites `key: true` to `key: <v>` on line n.
func (c *Ctx) setBoolLine(file string, n int, v bool) (model.Edit, bool) {
	l, ok := c.line(file, n)
	if !ok || !boolVal.MatchString(l) {
		return model.Edit{}, false
	}
	return c.replaceLine(file, n, boolVal.ReplaceAllString(l, fmt.Sprintf("${1}%t", v)))
}

func indentOf(l string) string {
	return l[:len(l)-len(strings.TrimLeft(l, " \t"))]
}

// insertBefore inserts text (already indented) before line n.
func (c *Ctx) insertBefore(file string, n int, text string) (model.Edit, bool) {
	if _, ok := c.line(file, n); !ok {
		return model.Edit{}, false
	}
	return model.Edit{File: file, StartLine: n, EndLine: n - 1, Replace: text}, true
}

func ptr[T any](v T) *T { return &v }

func edits(es ...model.Edit) []model.Edit { return es }

// ok wraps (edit, ok) into a slice so fix builders can drop failed edits.
func okEdits(e model.Edit, ok bool) []model.Edit {
	if !ok {
		return nil
	}
	return []model.Edit{e}
}

// attrStrings reads a string list from Attrs regardless of whether the
// inventory came straight from a parser or through a JSON round trip.
func attrStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
