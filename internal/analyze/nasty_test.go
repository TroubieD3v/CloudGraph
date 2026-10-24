package analyze_test

import (
	"testing"
	"time"

	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

// Self-referencing YAML aliases must not recurse forever (a List containing
// itself used to overflow the stack).
func TestNastyRecursiveYAML(t *testing.T) {
	cases := map[string]string{
		"list-self.yaml":    "&root\napiVersion: v1\nkind: List\nitems:\n  - *root\n",
		"svc-self.yml":      "services: &s\n  a: *s\n",
		"merge.yaml":        "a: &a {x: 1}\nservices:\n  web:\n    <<: *a\n    image: nginx\n",
		"laughs.yaml":       "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\nservices: {x: {environment: *d}}\n",
		"pod-labels.yaml":   "apiVersion: v1\nkind: Pod\nmetadata: &m\n  name: p\n  labels: *m\nspec: {containers: [{name: c, image: i}]}\n",
		"alias-self.yaml":   "x: &a *a\n",
		"svc-alias.yml":     "services:\n  web: &w\n    image: *w\n    ports: *w\n    volumes: *w\n    environment: *w\n    networks: *w\n",
		"pod-alias.yaml":    "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: &s\n  containers: [*s]\n  volumes: [*s]\n",
		"deploy-alias.yaml": "apiVersion: v1\nkind: Deployment\nmetadata: {name: p}\nspec: &s\n  template: *s\n",
		"netpol-alias.yaml": "apiVersion: v1\nkind: NetworkPolicy\nmetadata: {name: p}\nspec: &s\n  ingress: [*s]\n  podSelector: *s\n",
	}
	for name, body := range cases {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _, _ = analyze.Run("nasty", []parse.File{{Name: name, Data: []byte(body)}})
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s hangs", name)
		}
	}
}
