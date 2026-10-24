package paths_test

import (
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/testutil"
)

func TestInsecureKubernetesPaths(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	titles := strings.Join(testutil.PathTitles(a), "\n")
	for _, want := range []string{
		"web → Read Kubernetes Secrets (cluster-wide)",
		"api → Kubernetes node (host)",
		"web → postgres",
		"debug-binding → Exec into other pods (cluster-wide)",
	} {
		if !strings.Contains(titles, want) {
			t.Errorf("missing path %q in:\n%s", want, titles)
		}
	}
}

func TestPathsAreConditionalAndExplainable(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	p := testutil.FindPath(a, "web → Read Kubernetes Secrets (cluster-wide)")
	if p == nil {
		t.Fatal("path not found")
	}
	if p.Confidence != model.Conditional {
		t.Errorf("a path through a workload compromise must be conditional, got %s", p.Confidence)
	}
	if p.Nodes[0] != "internet" || len(p.Steps) != len(p.Nodes)-1 {
		t.Errorf("malformed path: %+v", p.Nodes)
	}
	joined := strings.Join(p.Prerequisites, " | ")
	if !strings.Contains(joined, "code execution") {
		t.Errorf("prerequisites must state the compromise assumption: %s", joined)
	}
	for _, s := range p.Steps {
		if s.Src.File == "" || s.Src.Line == 0 {
			t.Errorf("step %q is not traceable to a line: %+v", s.Label, s.Src)
		}
	}
	if !strings.Contains(p.Explanation, "does not prove") {
		t.Error("explanation must not claim exploitation is proven")
	}
}

func TestUnknownEdgesAreNeverTraversed(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	// redis is only reachable through an ipBlock NetworkPolicy: Unknown, so no path may end there.
	for _, p := range a.Paths {
		if strings.HasSuffix(p.Target, "/redis") {
			t.Errorf("path through unknown reachability: %s", p.Title)
		}
		for _, s := range p.Steps {
			if s.Confidence == model.Unknown {
				t.Errorf("unknown step in path %s", p.Title)
			}
		}
	}
}

func TestVulnerableComposeAndTerraform(t *testing.T) {
	a := testutil.Demo(t, "vulnerable-ecommerce")
	for _, want := range []string{
		"frontend → Docker host",
		"aws_instance.app → AWS account administrator",
		"Internet exposes db",
		"Internet exposes aws_db_instance.orders",
	} {
		if testutil.FindPath(a, want) == nil {
			t.Errorf("missing path %q; have %v", want, testutil.PathTitles(a))
		}
	}
}

func TestPathsAreSortedByScore(t *testing.T) {
	a := testutil.Demo(t, "vulnerable-all")
	for i := 1; i < len(a.Paths); i++ {
		if a.Paths[i-1].Score < a.Paths[i].Score {
			t.Fatalf("paths not sorted: %d then %d", a.Paths[i-1].Score, a.Paths[i].Score)
		}
	}
}

func TestSingleTierAppDoesNotReportIntendedDatabaseAccessAsPivotChain(t *testing.T) {
	// frontend -> backend -> db is the intended architecture: two pivots must not be reported.
	a := testutil.Demo(t, "hardened-infrastructure")
	if len(a.Paths) != 0 {
		t.Errorf("unexpected paths: %v", testutil.PathTitles(a))
	}
}

func TestHotspots(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	if len(a.Hotspots) == 0 {
		t.Fatal("expected hotspots (web-sa participates in several paths)")
	}
	found := false
	for _, h := range a.Hotspots {
		if strings.HasSuffix(h.ResourceID, "ServiceAccount/shop/web-sa") && h.Paths >= 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("web-sa should be a hotspot: %+v", a.Hotspots)
	}
}
