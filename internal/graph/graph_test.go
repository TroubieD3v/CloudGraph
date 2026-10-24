package graph_test

import (
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/testutil"
)

func hasEdge(a *model.Analysis, from, to, typ string) *model.Edge {
	for _, e := range a.Edges {
		if e.From == from && e.To == to && e.Type == typ {
			return e
		}
	}
	return nil
}

func unknownContaining(a *model.Analysis, s string) bool {
	for _, u := range a.Unknowns {
		if strings.Contains(u.Message, s) {
			return true
		}
	}
	return false
}

const ingressMissingService = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ing
  namespace: a
spec:
  rules:
    - http:
        paths:
          - backend:
              service:
                name: ghost
`

func TestMissingServiceYieldsUnknownNotAnEdge(t *testing.T) {
	a := testutil.Scan(t, "i.yaml", ingressMissingService)
	if !unknownContaining(a, `"ghost"`) {
		t.Errorf("expected an Unknown note for the missing Service, got %+v", a.Unknowns)
	}
	for _, e := range a.Edges {
		if e.Type == "routes_to" {
			t.Errorf("must not invent a routes_to edge: %+v", e)
		}
	}
}

func TestServiceSelectingNothingIsUnknown(t *testing.T) {
	a := testutil.Scan(t, "s.yaml", "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n  namespace: a\nspec:\n  selector:\n    app: nobody\n")
	if !unknownContaining(a, "matches no workload") {
		t.Errorf("expected Unknown, got %+v", a.Unknowns)
	}
	for _, e := range a.Edges {
		if e.Type == "selects" {
			t.Error("selects edge invented")
		}
	}
}

const twoPods = `apiVersion: v1
kind: Pod
metadata:
  name: front
  namespace: a
  labels: {app: front}
spec:
  containers: [{name: c, image: nginx:1}]
---
apiVersion: v1
kind: Pod
metadata:
  name: db
  namespace: a
  labels: {app: db}
spec:
  containers: [{name: c, image: postgres:16}]
`

func TestNetworkPolicySemantics(t *testing.T) {
	t.Run("no policy means reachable (conditional, never confirmed)", func(t *testing.T) {
		a := testutil.Scan(t, "p.yaml", twoPods)
		e := hasEdge(a, "k8s:Pod/a/front", "k8s:Pod/a/db", "network_reach")
		if e == nil {
			t.Fatal("expected network_reach edge")
		}
		if e.Confidence == model.Confirmed {
			t.Error("absence of NetworkPolicy must never be reported as confirmed")
		}
	})
	t.Run("default deny removes the edge", func(t *testing.T) {
		deny := "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny\n  namespace: a\nspec:\n  podSelector: {}\n  policyTypes: [Ingress]\n"
		a := testutil.Scan(t, "p.yaml", twoPods+deny)
		if hasEdge(a, "k8s:Pod/a/front", "k8s:Pod/a/db", "network_reach") != nil {
			t.Error("default-deny policy should isolate db")
		}
	})
	t.Run("pod selector allow rule re-opens only matching pods", func(t *testing.T) {
		np := "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: allow\n  namespace: a\nspec:\n  podSelector:\n    matchLabels: {app: db}\n  ingress:\n    - from:\n        - podSelector:\n            matchLabels: {app: front}\n"
		a := testutil.Scan(t, "p.yaml", twoPods+np)
		if hasEdge(a, "k8s:Pod/a/front", "k8s:Pod/a/db", "network_reach") == nil {
			t.Error("front should be allowed by policy")
		}
	})
	t.Run("ipBlock peers cannot be resolved", func(t *testing.T) {
		np := "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: ip\n  namespace: a\nspec:\n  podSelector:\n    matchLabels: {app: db}\n  ingress:\n    - from:\n        - ipBlock: {cidr: 10.0.0.0/8}\n"
		a := testutil.Scan(t, "p.yaml", twoPods+np)
		if hasEdge(a, "k8s:Pod/a/front", "k8s:Pod/a/db", "network_reach") != nil {
			t.Error("must not assume reachability through an ipBlock")
		}
		if !unknownContaining(a, "ipBlock") {
			t.Errorf("expected Unknown about ipBlock: %+v", a.Unknowns)
		}
	})
	t.Run("matchExpressions are Unknown", func(t *testing.T) {
		np := "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: expr\n  namespace: a\nspec:\n  podSelector:\n    matchExpressions:\n      - {key: app, operator: In, values: [db]}\n"
		a := testutil.Scan(t, "p.yaml", twoPods+np)
		if hasEdge(a, "k8s:Pod/a/front", "k8s:Pod/a/db", "network_reach") != nil || !unknownContaining(a, "matchExpressions") {
			t.Errorf("expected Unknown without edge: %+v", a.Unknowns)
		}
	})
}

func TestRBACBindingToUnknownRoleIsUnknown(t *testing.T) {
	a := testutil.Scan(t, "r.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: b
subjects:
  - kind: ServiceAccount
    name: sa
    namespace: a
roleRef:
  kind: ClusterRole
  name: custom-role-not-in-input
`)
	if !unknownContaining(a, "custom-role-not-in-input") {
		t.Errorf("expected Unknown, got %+v", a.Unknowns)
	}
}

func TestAutomountFalseRemovesTokenEdge(t *testing.T) {
	a := testutil.Scan(t, "p.yaml", `apiVersion: v1
kind: Pod
metadata: {name: p, namespace: a}
spec:
  automountServiceAccountToken: false
  containers: [{name: c, image: x:1}]
`)
	e := hasEdge(a, "k8s:Pod/a/p", "k8s:ServiceAccount/a/default", "runs_as")
	if e == nil || e.Attack {
		t.Errorf("token not mounted: the runs_as edge must not be an attack edge: %+v", e)
	}
}

func TestComposeSeparateNetworksAreNotConnected(t *testing.T) {
	a := testutil.Scan(t, "c.yml", `services:
  web:
    image: nginx:1
    networks: [front]
  db:
    image: postgres:16
    networks: [back]
networks:
  front: {}
  back: {}
`)
	if hasEdge(a, "compose:service/web", "compose:service/db", "network_reach") != nil {
		t.Error("services on different networks must not be connected")
	}
}

func TestComposeLoopbackPortIsNotExposed(t *testing.T) {
	a := testutil.Scan(t, "c.yml", "services:\n  db:\n    image: postgres:16\n    ports: [\"127.0.0.1:5432:5432\"]\n")
	if hasEdge(a, "internet", "compose:service/db", "exposes") != nil {
		t.Error("loopback-bound port is not Internet exposure")
	}
}

func TestEdgesCarryConfidenceAndSource(t *testing.T) {
	a := testutil.Demo(t, "insecure-kubernetes")
	for _, e := range a.Edges {
		if e.Confidence == "" || e.ID == "" || e.Label == "" {
			t.Errorf("edge incomplete: %+v", e)
		}
		if e.Attack && e.Src.File == "" {
			t.Errorf("attack edge without source reference: %+v", e)
		}
	}
}
