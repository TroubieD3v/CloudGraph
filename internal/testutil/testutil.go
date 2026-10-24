// Package testutil holds helpers shared by the test suites.
package testutil

import (
	"testing"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

// Demo analyses a bundled demo project.
func Demo(t testing.TB, name string) *model.Analysis {
	t.Helper()
	files, err := examples.Files(name)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := analyze.Run("demo:"+name, files)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Scan analyses inline documents given as name, content pairs.
func Scan(t testing.TB, pairs ...string) *model.Analysis {
	t.Helper()
	var files []parse.File
	for i := 0; i+1 < len(pairs); i += 2 {
		files = append(files, parse.File{Name: pairs[i], Data: []byte(pairs[i+1])})
	}
	a, _, err := analyze.Run("test", files)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// HasRule reports whether a finding of rule id exists (optionally for a resource ID substring).
func HasRule(a *model.Analysis, id string) bool {
	for _, f := range a.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// PathTitles returns the titles of all paths.
func PathTitles(a *model.Analysis) []string {
	var out []string
	for _, p := range a.Paths {
		out = append(out, p.Title)
	}
	return out
}

// FindPath returns the first path with the given title.
func FindPath(a *model.Analysis, title string) *model.Path {
	for _, p := range a.Paths {
		if p.Title == title {
			return p
		}
	}
	return nil
}
