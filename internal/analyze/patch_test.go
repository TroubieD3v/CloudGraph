package analyze_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

// applyZeroContext applies a patch produced by analyze.Patch (zero-context
// unified diff, as used with `git apply --unidiff-zero`) to in-memory files.
func applyZeroContext(t *testing.T, files map[string][]string, patch string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for k, v := range files {
		out[k] = append([]string(nil), v...)
	}
	type hunk struct {
		oldStart, oldCount int
		minus, plus        []string
	}
	var file string
	hunks := map[string][]hunk{}
	var cur *hunk
	flush := func() {
		if cur != nil {
			hunks[file] = append(hunks[file], *cur)
			cur = nil
		}
	}
	for _, l := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(l, "#"):
		case strings.HasPrefix(l, "--- "):
			flush()
		case strings.HasPrefix(l, "+++ b/"):
			file = strings.TrimPrefix(l, "+++ b/")
		case strings.HasPrefix(l, "@@ "):
			flush()
			var os, oc, ns, nc int
			if _, err := fmt.Sscanf(l, "@@ -%d,%d +%d,%d @@", &os, &oc, &ns, &nc); err != nil {
				t.Fatalf("bad hunk header %q", l)
			}
			cur = &hunk{oldStart: os, oldCount: oc}
		case strings.HasPrefix(l, "-") && cur != nil:
			cur.minus = append(cur.minus, l[1:])
		case strings.HasPrefix(l, "+") && cur != nil:
			cur.plus = append(cur.plus, l[1:])
		}
	}
	flush()
	for name, hs := range hunks {
		lines := out[name]
		// apply from the bottom so earlier line numbers stay valid
		sort.Slice(hs, func(i, j int) bool { return hs[i].oldStart > hs[j].oldStart })
		for _, h := range hs {
			start := h.oldStart - 1 // index of first replaced line
			if h.oldCount == 0 {
				start = h.oldStart // insertion after line oldStart
			}
			for i, m := range h.minus {
				if lines[start+i] != m {
					t.Fatalf("%s: context mismatch at line %d: have %q, patch expects %q", name, start+i+1, lines[start+i], m)
				}
			}
			next := append(append(append([]string(nil), lines[:start]...), h.plus...), lines[start+h.oldCount:]...)
			lines = next
		}
		out[name] = lines
	}
	return out
}

func TestExportedPatchAppliesAndMatchesSimulation(t *testing.T) {
	for _, demo := range []string{"insecure-kubernetes", "vulnerable-ecommerce"} {
		t.Run(demo, func(t *testing.T) {
			files, err := examples.Files(demo)
			if err != nil {
				t.Fatal(err)
			}
			a, inv, err := analyze.Run(demo, files)
			if err != nil {
				t.Fatal(err)
			}
			var mechanical []string
			for _, f := range a.Fixes {
				if len(f.Edits) > 0 {
					mechanical = append(mechanical, f.ID)
				}
			}
			patch, _ := analyze.Patch(a, mechanical, inv.Files)
			if strings.Contains(patch, "SKIPPED") {
				t.Errorf("patch has overlapping edits:\n%s", patch)
			}
			patched := applyZeroContext(t, inv.Files, patch)

			var newFiles []parse.File
			for name, lines := range patched {
				newFiles = append(newFiles, parse.File{Name: name, Data: []byte(strings.Join(lines, "\n"))})
			}
			sort.Slice(newFiles, func(i, j int) bool { return newFiles[i].Name < newFiles[j].Name })
			after, inv2, err := analyze.Run(demo+" patched", newFiles)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range inv2.Warnings {
				if strings.Contains(w, "invalid") {
					t.Errorf("patched file no longer parses: %s", w)
				}
			}
			sim, err := analyze.Simulate(a, mechanical)
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Paths) != sim.PathsAfter {
				t.Errorf("real patch leaves %d paths, simulation predicted %d", len(after.Paths), sim.PathsAfter)
			}
			if len(after.Findings) > sim.FindingsAfter {
				t.Errorf("real patch leaves %d findings, simulation predicted %d", len(after.Findings), sim.FindingsAfter)
			}
			t.Logf("%s: %d mechanical fixes, paths %d -> %d, findings %d -> %d",
				demo, len(mechanical), len(a.Paths), len(after.Paths), len(a.Findings), len(after.Findings))
		})
	}
}
