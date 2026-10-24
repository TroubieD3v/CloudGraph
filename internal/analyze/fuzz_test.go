package analyze_test

import (
	"testing"
	"time"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

// FuzzAnalyze feeds arbitrary documents through the whole pipeline. Untrusted
// configuration must never crash the engine. Run longer with:
//
//	go test ./internal/analyze -run '^$' -fuzz FuzzAnalyze -fuzztime 60s
func FuzzAnalyze(f *testing.F) {
	for _, demo := range []string{"insecure-kubernetes", "vulnerable-ecommerce"} {
		files, err := examples.Files(demo)
		if err != nil {
			f.Fatal(err)
		}
		for _, file := range files {
			f.Add(file.Name, file.Data)
		}
	}
	f.Add("a.yaml", []byte("apiVersion: v1\nkind: List\nitems: [{kind: Pod, metadata: {name: x}, spec: {containers: [{}]}}]"))
	f.Add("c.yml", []byte("services:\n  a:\n    ports: [{target: 1}, \"x:y:z:w\", 80]\n    volumes: [{}, \":\"]\n"))
	f.Add("p.json", []byte(`{"format_version":"1","planned_values":{"root_module":{"resources":[{"type":"aws_instance","values":null}]}}}`))
	f.Add("anchors.yaml", []byte("x: &a [*a]\nservices: *a\n"))
	f.Add("list.yaml", []byte("&root\napiVersion: v1\nkind: List\nitems:\n  - *root\n"))

	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		done := make(chan error, 1)
		go func() {
			for _, n := range []string{name, "fuzz.yaml", "fuzz.json"} {
				a, _, err := analyze.Run("fuzz", []parse.File{{Name: n, Data: data}})
				if err != nil {
					continue
				}
				var ids []string
				for _, fx := range a.Fixes {
					ids = append(ids, fx.ID)
				}
				if _, err := analyze.Simulate(a, ids); err != nil {
					done <- err
					return
				}
				analyze.Patch(a, ids, nil)
			}
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("simulate: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("analysis did not finish within 5s for %q (%d bytes)", name, len(data))
		}
	})
}
