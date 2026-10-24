package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/server"
	"github.com/TroubieD3v/cloudgraph/internal/store"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ts := httptest.NewServer(server.New(st, nil).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, ts *httptest.Server, method, path, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	return resp, []byte(buf.String())
}

func createDemo(t *testing.T, ts *httptest.Server, demo string) model.Analysis {
	t.Helper()
	resp, body := do(t, ts, "POST", "/api/analyses", `{"demo":"`+demo+`"}`, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create %s: %d %s", demo, resp.StatusCode, body)
	}
	var a model.Analysis
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAnalysisLifecycle(t *testing.T) {
	ts := newServer(t)
	a := createDemo(t, ts, "insecure-kubernetes")
	if a.Summary.Paths == 0 || a.ID == "" {
		t.Fatalf("bad analysis: %+v", a.Summary)
	}

	resp, body := do(t, ts, "GET", "/api/analyses", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), a.ID) {
		t.Errorf("list: %d %s", resp.StatusCode, body)
	}
	resp, _ = do(t, ts, "GET", "/api/analyses/"+a.ID, "", nil)
	if resp.StatusCode != 200 {
		t.Errorf("get: %d", resp.StatusCode)
	}

	// simulate
	var fixID string
	for _, f := range a.Fixes {
		if f.Action == "set_automount" {
			fixID = f.ID
		}
	}
	resp, body = do(t, ts, "POST", "/api/analyses/"+a.ID+"/simulate", `{"fixes":["`+fixID+`"]}`, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"pathsResolved"`) {
		t.Fatalf("simulate: %d %s", resp.StatusCode, body)
	}
	var sim struct {
		PathsBefore int `json:"pathsBefore"`
		PathsAfter  int `json:"pathsAfter"`
	}
	_ = json.Unmarshal(body, &sim)
	if sim.PathsAfter >= sim.PathsBefore {
		t.Errorf("simulation did not reduce paths: %+v", sim)
	}

	// patch
	resp, body = do(t, ts, "POST", "/api/analyses/"+a.ID+"/patch", `{"fixes":["`+fixID+`"]}`, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "automountServiceAccountToken") {
		t.Errorf("patch: %d %s", resp.StatusCode, body)
	}

	// reports
	for ext, want := range map[string]string{"sarif": `"2.1.0"`, "json": `"resources"`, "html": "<!doctype html>"} {
		resp, body = do(t, ts, "GET", "/api/analyses/"+a.ID+"/report/"+ext, "", nil)
		if resp.StatusCode != 200 || !strings.Contains(string(body), want) {
			t.Errorf("report.%s: %d", ext, resp.StatusCode)
		}
	}

	// diff
	h := createDemo(t, ts, "hardened-infrastructure")
	resp, body = do(t, ts, "GET", "/api/diff?a="+a.ID+"&b="+h.ID, "", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "pathsDisappeared") {
		t.Errorf("diff: %d %s", resp.StatusCode, body)
	}

	// delete
	resp, _ = do(t, ts, "DELETE", "/api/analyses/"+a.ID, "", nil)
	if resp.StatusCode != 204 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	resp, _ = do(t, ts, "GET", "/api/analyses/"+a.ID, "", nil)
	if resp.StatusCode != 404 {
		t.Errorf("deleted analysis still found: %d", resp.StatusCode)
	}
}

func TestUploadedFiles(t *testing.T) {
	ts := newServer(t)
	body := `{"name":"mine","files":[{"name":"docker-compose.yml","content":"services:\n  db:\n    image: postgres:16\n    ports: [\"5432:5432\"]\n"}]}`
	resp, out := do(t, ts, "POST", "/api/analyses", body, nil)
	if resp.StatusCode != 201 || !strings.Contains(string(out), "CG-DC-007") {
		t.Fatalf("upload: %d %s", resp.StatusCode, out)
	}
}

func TestBadRequests(t *testing.T) {
	ts := newServer(t)
	cases := []struct {
		name, body string
		want       int
	}{
		{"empty", `{}`, 400},
		{"unknown demo", `{"demo":"nope"}`, 404},
		{"path traversal", `{"files":[{"name":"../../etc/passwd","content":"x"}]}`, 400},
		{"unsupported content", `{"files":[{"name":"x.yaml","content":"hello: world"}]}`, 422},
		{"malformed json", `{`, 400},
	}
	for _, c := range cases {
		resp, _ := do(t, ts, "POST", "/api/analyses", c.body, nil)
		if resp.StatusCode != c.want {
			t.Errorf("%s: got %d want %d", c.name, resp.StatusCode, c.want)
		}
	}
}

func TestCrossOriginWritesAreRejected(t *testing.T) {
	ts := newServer(t)
	resp, _ := do(t, ts, "POST", "/api/analyses", `{"demo":"insecure-kubernetes"}`, map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != 403 {
		t.Errorf("cross-origin POST not rejected: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/analyses", strings.NewReader(`demo=x`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 415 {
		t.Errorf("form posts must be rejected: %d", r2.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	ts := newServer(t)
	resp, _ := do(t, ts, "GET", "/api/health", "", nil)
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("security headers missing")
	}
}

func TestEmptyCollectionsAreArraysNotNull(t *testing.T) {
	ts := newServer(t)
	a := createDemo(t, ts, "hardened-infrastructure")
	_, body := do(t, ts, "GET", "/api/analyses/"+a.ID, "", nil)
	for _, field := range []string{"paths", "findings", "fixes", "hotspots"} {
		if !strings.Contains(string(body), `"`+field+`":[]`) {
			t.Errorf("%s must serialise as [] when empty", field)
		}
	}
	// simulation and patch responses too: the UI iterates over these without null checks
	_, body = do(t, ts, "POST", "/api/analyses/"+a.ID+"/simulate", `{"fixes":[]}`, nil)
	for _, field := range []string{"pathsResolved", "pathsRemaining", "pathsNew", "findingsResolved", "applied"} {
		if !strings.Contains(string(body), `"`+field+`":[]`) {
			t.Errorf("simulate: %s must be []: %s", field, body)
		}
	}
	_, body = do(t, ts, "POST", "/api/analyses/"+a.ID+"/patch", `{"fixes":[]}`, nil)
	if !strings.Contains(string(body), `"manual":[]`) {
		t.Errorf("patch manual must be []: %s", body)
	}
}

func TestSearchLimitsPerAnalysis(t *testing.T) {
	ts := newServer(t)
	resp, _ := do(t, ts, "POST", "/api/analyses", `{"demo":"insecure-kubernetes","limits":{"maxDepth":99}}`, nil)
	if resp.StatusCode != 400 {
		t.Errorf("out-of-range limit must be rejected, got %d", resp.StatusCode)
	}
	resp, body := do(t, ts, "POST", "/api/analyses", `{"demo":"insecure-kubernetes","limits":{"maxDepth":4}}`, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var a model.Analysis
	_ = json.Unmarshal(body, &a)
	if a.PathSearch.Limits.MaxDepth != 4 || a.PathSearch.Limits.MaxPivots != 1 || a.PathSearch.Complete {
		t.Fatalf("partial override must keep other defaults and report truncation: %+v", a.PathSearch)
	}
	// What-if must recompute with the same limits, otherwise it would "resolve" paths it simply did not search.
	resp, body = do(t, ts, "POST", "/api/analyses/"+a.ID+"/simulate", `{"fixes":[]}`, nil)
	var sim struct {
		PathsBefore int `json:"pathsBefore"`
		PathsAfter  int `json:"pathsAfter"`
	}
	_ = json.Unmarshal(body, &sim)
	if resp.StatusCode != 200 || sim.PathsBefore != sim.PathsAfter {
		t.Errorf("an empty simulation must not change the path count: %d %+v", resp.StatusCode, sim)
	}
}
