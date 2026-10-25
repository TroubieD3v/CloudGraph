package paths_test

import (
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/graph"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
	"github.com/TroubieD3v/cloudgraph/internal/paths"
	"github.com/TroubieD3v/cloudgraph/internal/report"
	"github.com/TroubieD3v/cloudgraph/internal/testutil"
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

// twoHop is a stack whose only dangerous chain needs two network pivots:
// Internet -> gateway (published) -> app -> db. gateway and db share no network.
const twoHop = `
services:
  gateway:
    image: nginx:1.27.2
    ports: ["8080:80"]
    networks: [edge]
  app:
    image: acme/app:1.0.0
    networks: [edge, data]
  db:
    image: postgres:16.4
    networks: [data]
networks:
  edge: {}
  data: {}
`

func analyseTwoHop(t *testing.T, mutate func(*model.SearchLimits)) *model.Analysis {
	t.Helper()
	lim := model.DefaultSearchLimits()
	mutate(&lim)
	a, _, err := analyze.RunWith("two-hop", []parse.File{{Name: "docker-compose.yml", Data: []byte(twoHop)}}, lim)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPathNeedingTwoPivotsIsFoundOnlyWithTwoPivots(t *testing.T) {
	two := analyseTwoHop(t, func(l *model.SearchLimits) { l.MaxPivots = 2 })
	if testutil.FindPath(two, "gateway → db") == nil {
		t.Fatalf("the fixture must contain a two-pivot path, have %v", testutil.PathTitles(two))
	}
	if two.PathSearch.ScopeLimited || !two.PathSearch.SearchComplete {
		t.Errorf("with enough pivots nothing is left out: %+v", two.PathSearch)
	}

	one := analyseTwoHop(t, func(l *model.SearchLimits) { l.MaxPivots = 1 })
	if len(one.Paths) != 0 {
		t.Fatalf("one pivot must not reach db: %v", testutil.PathTitles(one))
	}
	s := one.PathSearch
	if !s.SearchComplete || !s.Complete {
		t.Errorf("the search itself ran to the end: %+v", s)
	}
	if !s.ScopeLimited || s.PivotLimitHits == 0 {
		t.Fatalf("an empty result produced under a pivot limit must say its scope was limited: %+v", s)
	}
	notices := strings.Join(s.Notices, "\n")
	for _, want := range []string{"Limited coverage", "--max-pivots"} {
		if !strings.Contains(notices, want) {
			t.Errorf("notice %q missing from %q", want, notices)
		}
	}
	text := &strings.Builder{}
	report.Text(text, one)
	if !strings.Contains(text.String(), "Limited coverage") {
		t.Errorf("the terminal report must state the limited coverage:\n%s", text)
	}
	if !strings.Contains(text.String(), "Search: complete; LIMITED COVERAGE") {
		t.Errorf("the terminal report must open with the search status:\n%s", text)
	}
}

func TestScopeLimitedIsSetByEveryLimit(t *testing.T) {
	g := demoGraph(t, "insecure-kubernetes")
	full, s := paths.FindWith(g, model.DefaultSearchLimits())
	if len(full) == 0 || s.ScopeLimited != (s.PivotLimitHits > 0) {
		t.Errorf("under default limits ScopeLimited must follow the pivot hits: %+v", s)
	}
	lim := model.DefaultSearchLimits()
	lim.MaxDepth = 4
	if _, s := paths.FindWith(g, lim); s.SearchComplete || !s.ScopeLimited {
		t.Errorf("a depth cut is both incomplete and scope-limited: %+v", s)
	}
}

func TestCoverageNamesWhatWasAnalysed(t *testing.T) {
	a := analyseTwoHop(t, func(*model.SearchLimits) {})
	c := a.PathSearch.Coverage
	if c.ResourceKinds[model.KindWorkload] != 3 {
		t.Errorf("three workloads expected: %+v", c.ResourceKinds)
	}
	if c.EdgeTypes["exposes"] == 0 || c.EdgeTypes["network_reach"] == 0 {
		t.Errorf("followable relationship types missing: %+v", c.EdgeTypes)
	}

	const plan = `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
	  {"address":"aws_instance.app","mode":"managed","type":"aws_instance","name":"app","values":{}},
	  {"address":"aws_vpc.main","mode":"managed","type":"aws_vpc","name":"main","values":{}},
	  {"address":"aws_subnet.a","mode":"managed","type":"aws_subnet","name":"a","values":{}},
	  {"address":"aws_subnet.b","mode":"managed","type":"aws_subnet","name":"b","values":{}}]}}}`
	tf, _, err := analyze.Run("tf", []parse.File{{Name: "plan.json", Data: []byte(plan)}})
	if err != nil {
		t.Fatal(err)
	}
	got := tf.PathSearch.Coverage.UnmodelledTypes
	if got["aws_vpc"] != 1 || got["aws_subnet"] != 2 || got["aws_instance"] != 0 {
		t.Errorf("unsupported Terraform types must be counted, supported ones not: %v", got)
	}
}

func TestSimilarRoutesAreCountedAndKeptOnRequest(t *testing.T) {
	more := func(l *model.SearchLimits) { l.MaxPivots = 3 }
	// worker gives a second way from gateway to db through app.
	src := strings.Replace(twoHop, "networks:\n  edge: {}", "  worker:\n    image: acme/worker:1.0.0\n    networks: [edge, data]\nnetworks:\n  edge: {}", 1)
	run := func(show bool) *model.Analysis {
		lim := model.DefaultSearchLimits()
		more(&lim)
		lim.ShowAlternatives = show
		a, _, err := analyze.RunWith("alt", []parse.File{{Name: "docker-compose.yml", Data: []byte(src)}}, lim)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	var out strings.Builder
	report.Text(&out, run(false))
	if !strings.Contains(out.String(), "similar route(s) merged") {
		t.Errorf("the terminal report must say that routes were merged:\n%s", out.String())
	}
	out.Reset()
	report.Text(&out, run(true))
	if !strings.Contains(out.String(), "alternative routes") {
		t.Errorf("the terminal report must list the alternatives on request:\n%s", out.String())
	}

	merged := testutil.FindPath(run(false), "gateway → db")
	if merged == nil || merged.SimilarRoutes == 0 {
		t.Fatalf("merged routes must be counted even when not shown: %+v", merged)
	}
	if len(merged.Alternatives) != 0 {
		t.Errorf("alternatives are opt-in, got %d", len(merged.Alternatives))
	}

	shown := testutil.FindPath(run(true), "gateway → db")
	if shown == nil || len(shown.Alternatives) != shown.SimilarRoutes || len(shown.Alternatives) == 0 {
		t.Fatalf("every merged route must be listed: %+v", shown)
	}
	if shown.Signature != merged.Signature {
		t.Errorf("showing alternatives must not change the representative route: %s vs %s", shown.Signature, merged.Signature)
	}
	seen := map[string]bool{shown.Signature: true}
	for _, alt := range shown.Alternatives {
		if alt.Target != shown.Target || alt.Nodes[1] != shown.Nodes[1] {
			t.Errorf("alternative must start and end like the path: %s", alt.Signature)
		}
		if seen[alt.Signature] {
			t.Errorf("duplicate route %s", alt.Signature)
		}
		seen[alt.Signature] = true
		if !strings.HasPrefix(alt.ID, shown.ID+"-alt-") {
			t.Errorf("alternative id %q", alt.ID)
		}
	}
}
