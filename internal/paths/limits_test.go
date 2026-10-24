package paths_test

import (
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/graph"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
	"github.com/TroubieD3v/cloudgraph/internal/paths"
)

func demoGraph(t *testing.T, name string) *graph.Graph {
	t.Helper()
	files, err := examples.Files(name)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := parse.Parse(files)
	if err != nil {
		t.Fatal(err)
	}
	return graph.Build(inv.Resources)
}

func TestDefaultLimitsAreNotReachedOnDemos(t *testing.T) {
	for _, d := range []string{"vulnerable-all", "insecure-kubernetes", "hardened-infrastructure"} {
		_, s := paths.FindWith(demoGraph(t, d), model.DefaultSearchLimits())
		if !s.Complete || s.CandidateLimitHit || s.DepthLimitHits != 0 {
			t.Errorf("%s: default limits must not truncate the demos: %+v", d, s)
		}
		for _, n := range s.Notices {
			if strings.HasPrefix(n, "Incomplete") {
				t.Errorf("%s: unexpected notice %q", d, n)
			}
		}
	}
}

func TestDepthLimitIsReported(t *testing.T) {
	g := demoGraph(t, "insecure-kubernetes")
	full, _ := paths.FindWith(g, model.DefaultSearchLimits())
	lim := model.DefaultSearchLimits()
	lim.MaxDepth = 4
	short, s := paths.FindWith(g, lim)
	if s.Complete || s.DepthLimitHits == 0 {
		t.Fatalf("depth limit of 4 must be reported as incomplete: %+v", s)
	}
	if len(short) >= len(full) {
		t.Errorf("a shallower search should find fewer paths: %d vs %d", len(short), len(full))
	}
	if !strings.Contains(strings.Join(s.Notices, " "), "--max-depth") {
		t.Errorf("notice should tell how to raise the limit: %v", s.Notices)
	}
}

func TestCandidateLimitIsReported(t *testing.T) {
	lim := model.DefaultSearchLimits()
	lim.MaxCandidates = 1
	ps, s := paths.FindWith(demoGraph(t, "vulnerable-all"), lim)
	if !s.CandidateLimitHit || s.Complete || s.Candidates != 1 || len(ps) != 1 {
		t.Fatalf("candidate cap must stop the search and be reported: paths=%d %+v", len(ps), s)
	}
	if !strings.Contains(strings.Join(s.Notices, " "), "--max-paths") {
		t.Errorf("notice missing: %v", s.Notices)
	}
}

func TestPivotLimitIsAScopeNoteNotATruncation(t *testing.T) {
	g := demoGraph(t, "vulnerable-all")
	none := model.DefaultSearchLimits()
	none.MaxPivots = 0
	p0, s0 := paths.FindWith(g, none)
	p1, _ := paths.FindWith(g, model.DefaultSearchLimits())
	more := model.DefaultSearchLimits()
	more.MaxPivots = 2
	p2, _ := paths.FindWith(g, more)
	if !(len(p0) < len(p1) && len(p1) <= len(p2)) {
		t.Errorf("more pivots must never find fewer paths: %d, %d, %d", len(p0), len(p1), len(p2))
	}
	if s0.PivotLimitHits == 0 || !s0.Complete {
		t.Errorf("pivot limit is a scope choice: counted, but the search stays complete: %+v", s0)
	}
	for _, p := range p0 {
		for _, st := range p.Steps {
			if strings.Contains(st.EdgeID, ":network_reach") {
				t.Errorf("MaxPivots=0 must not use lateral movement: %s", p.Title)
			}
		}
	}
}

func TestLimitsValidation(t *testing.T) {
	bad := []model.SearchLimits{
		{MaxDepth: 0, MaxCandidates: 10, MaxPivots: 1},
		{MaxDepth: 21, MaxCandidates: 10, MaxPivots: 1},
		{MaxDepth: 5, MaxCandidates: 0, MaxPivots: 1},
		{MaxDepth: 5, MaxCandidates: 10, MaxPivots: 4},
		{MaxDepth: 5, MaxCandidates: 10, MaxPivots: -1},
	}
	for _, l := range bad {
		if l.Validate() == nil {
			t.Errorf("%+v should be rejected", l)
		}
	}
	if err := model.DefaultSearchLimits().Validate(); err != nil {
		t.Error(err)
	}
}
