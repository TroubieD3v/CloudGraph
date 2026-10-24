package analyze_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/testutil"
)

func fixFor(a *model.Analysis, action, containsDesc string) *model.Fix {
	for _, f := range a.Fixes {
		if f.Action == action && strings.Contains(f.Description, containsDesc) {
			return f
		}
	}
	return nil
}

func TestSimulateAutomountFixRemovesSharedPaths(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	fx := fixFor(a, "set_automount", "web")
	if fx == nil {
		t.Fatal("automount fix not offered")
	}
	res, err := analyze.Simulate(a, []string{fx.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.PathsResolved) < 3 {
		t.Errorf("one change to the web ServiceAccount token should resolve several chains, got %d", len(res.PathsResolved))
	}
	if len(res.PathsNew) != 0 {
		t.Errorf("a fix must not introduce paths: %v", res.PathsNew)
	}
	if res.PathsAfter != res.PathsBefore-len(res.PathsResolved) {
		t.Errorf("counts inconsistent: %d -> %d, resolved %d", res.PathsBefore, res.PathsAfter, len(res.PathsResolved))
	}
	// The original analysis must not be mutated.
	if len(a.Paths) != res.PathsBefore {
		t.Error("simulation mutated the original analysis")
	}
}

func TestSimulateRemoveBindingEliminatesAnonymousPaths(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	fx := fixFor(a, "remove_resource", "debug-binding")
	if fx == nil {
		t.Fatal("remove binding fix missing")
	}
	res, err := analyze.Simulate(a, []string{fx.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.After.Paths {
		if strings.HasPrefix(p.Title, "debug-binding") {
			t.Errorf("path survived removal of its binding: %s", p.Title)
		}
	}
	if len(res.PathsResolved) != 2 {
		t.Errorf("expected 2 resolved paths, got %d", len(res.PathsResolved))
	}
}

func TestSimulateAllFixesReachesZeroOrNearZero(t *testing.T) {
	a := testutil.Demo(t, "vulnerable-all")
	var ids []string
	for _, f := range a.Fixes {
		ids = append(ids, f.ID)
	}
	res, err := analyze.Simulate(a, ids)
	if err != nil {
		t.Fatal(err)
	}
	if res.PathsAfter >= res.PathsBefore || res.FindingsAfter >= res.FindingsBefore {
		t.Errorf("applying every fix should improve things: paths %d->%d findings %d->%d",
			res.PathsBefore, res.PathsAfter, res.FindingsBefore, res.FindingsAfter)
	}
	if len(res.PathsNew) != 0 {
		t.Errorf("new paths after fixes: %v", res.PathsNew)
	}
}

func TestSimulateWorksOnAnalysisReloadedFromJSON(t *testing.T) {
	a := testutil.Demo(t, "vulnerable-all")
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back model.Analysis
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range back.Fixes {
		ids = append(ids, f.ID)
	}
	direct, _ := analyze.Simulate(a, ids)
	viaJSON, err := analyze.Simulate(&back, ids)
	if err != nil {
		t.Fatal(err)
	}
	if direct.PathsAfter != viaJSON.PathsAfter || direct.FindingsAfter != viaJSON.FindingsAfter {
		t.Errorf("stored analysis simulates differently: %d/%d vs %d/%d",
			direct.PathsAfter, direct.FindingsAfter, viaJSON.PathsAfter, viaJSON.FindingsAfter)
	}
}

func TestSimulateUnknownFixIsReported(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	res, err := analyze.Simulate(a, []string{"fix-does-not-exist"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || len(res.Applied) != 0 {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestPatchContainsMechanicalEditsAndManualNotes(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	var ids []string
	for _, f := range a.Fixes {
		ids = append(ids, f.ID)
	}
	patch, manual := analyze.Patch(a, ids, nil)
	for _, want := range []string{"--- a/api.yaml", "-            privileged: true", "+            privileged: false", "--- /dev/null", "default-deny-shop.yaml"} {
		if !strings.Contains(patch, want) {
			t.Errorf("patch is missing %q", want)
		}
	}
	if len(manual) == 0 {
		t.Error("fixes without a mechanical edit must be listed as manual steps")
	}
	for _, secret := range []string{"demo-not-a-real-secret", "demo-only-password"} {
		if strings.Contains(patch, secret) {
			t.Errorf("patch leaks %q", secret)
		}
	}
}

func TestDiffHardenedVsVulnerable(t *testing.T) {
	v := testutil.Demo(t, "vulnerable-all")
	h := testutil.Demo(t, "hardened-infrastructure")
	d := analyze.Diff(v, h)
	if len(d.PathsDisappeared) == 0 || len(d.PathsAppeared) != 0 {
		t.Errorf("paths disappeared=%d appeared=%d", len(d.PathsDisappeared), len(d.PathsAppeared))
	}
	if len(d.FindingsRemoved) == 0 {
		t.Error("expected findings to disappear")
	}
	if d.Counts["paths"][0] != len(v.Paths) || d.Counts["paths"][1] != 0 {
		t.Errorf("counts wrong: %+v", d.Counts)
	}
	// A diff of identical states is empty.
	same := analyze.Diff(v, testutil.Demo(t, "vulnerable-all"))
	if len(same.PathsAppeared)+len(same.PathsDisappeared)+len(same.FindingsAdded)+len(same.FindingsRemoved)+len(same.EdgesAdded)+len(same.EdgesRemoved) != 0 {
		t.Errorf("identical inputs must diff to nothing: %+v", same)
	}
}
