package rules_test

import (
	"os"
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/rules"
	"github.com/TroubieD3v/cloudgraph/internal/testutil"
)

func TestEveryRuleFiresOnVulnerableExamples(t *testing.T) {
	k8s, _ := os.ReadFile("testdata/extra-k8s.yaml")
	tf, _ := os.ReadFile("testdata/extra-tf.json")
	extra := testutil.Scan(t, "extra-k8s.yaml", string(k8s), "extra-tf.json", string(tf))
	all := testutil.Demo(t, "vulnerable-all")

	for _, r := range rules.All() {
		if !testutil.HasRule(all, r.ID) && !testutil.HasRule(extra, r.ID) {
			t.Errorf("rule %s (%s) has no positive example", r.ID, r.Title)
		}
	}
}

func TestHardenedExamplesProduceNoFindingsOrPaths(t *testing.T) {
	a := testutil.Demo(t, "hardened-infrastructure")
	for _, f := range a.Findings {
		t.Errorf("unexpected finding %s on %s: %s", f.RuleID, f.ResourceID, f.Message)
	}
	if len(a.Paths) != 0 {
		t.Errorf("hardened infrastructure should have no attack paths, got %v", a.Paths)
	}
}

func TestRuleIDsAreUniqueAndDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range rules.All() {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Remediation == "" || r.Severity == "" || r.Domain == "" {
			t.Errorf("rule %s is missing metadata", r.ID)
		}
	}
	if len(seen) < 40 {
		t.Errorf("expected at least 40 rules, have %d", len(seen))
	}
}

// negative cases: a configuration that looks close to a violation but is safe.
func TestNegativeCases(t *testing.T) {
	cases := []struct {
		name  string
		rule  string
		files []string
	}{
		{"compose port bound to loopback", "CG-DC-007", []string{"c.yml", "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"127.0.0.1:5432:5432\"\n"}},
		{"compose env references variable", "CG-DC-008", []string{"c.yml", "services:\n  app:\n    image: app:1\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n"}},
		{"compose _FILE secret path", "CG-DC-008", []string{"c.yml", "services:\n  app:\n    image: app:1\n    environment:\n      DB_PASSWORD_FILE: /run/secrets/db\n"}},
		{"compose named volume", "CG-DC-003", []string{"c.yml", "services:\n  app:\n    image: app:1\n    volumes:\n      - data:/var/lib/app\n"}},
		{"compose pinned image", "CG-DC-009", []string{"c.yml", "services:\n  app:\n    image: app:1.2.3\n"}},
		{"k8s privileged false", "CG-K8S-001", []string{"k.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: i:1\n      securityContext:\n        privileged: false\n"}},
		{"k8s rbac limited by resourceNames", "CG-K8S-012", []string{"k.yaml", "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: r\n  namespace: a\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    resourceNames: [\"one\"]\n    verbs: [\"get\"]\n"}},
		{"k8s ingress with tls", "CG-K8S-016", []string{"k.yaml", "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: i\nspec:\n  tls:\n    - hosts: [a.example.com]\n  rules:\n    - host: a.example.com\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := testutil.Scan(t, c.files...)
			if testutil.HasRule(a, c.rule) {
				t.Errorf("rule %s must not fire", c.rule)
			}
		})
	}
}

func TestRulesDocIsUpToDate(t *testing.T) {
	want := rules.Markdown()
	got, err := os.ReadFile("../../docs/RULES.md")
	if err != nil || strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Fatal("docs/RULES.md is stale; regenerate with: go run ./cmd/cloudgraph rules --format markdown > docs/RULES.md")
	}
}
