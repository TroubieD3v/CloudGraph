package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/report"
	"github.com/TroubieD3v/cloudgraph/internal/testutil"
)

// Literal secrets present in the demo inputs; none may appear in any output.
var plantedSecrets = []string{
	"demo-password-123", "admin123", "demo-only-password", "not-a-real-secret",
	"demo-not-a-real-secret",
}

func TestSecretsNeverAppearInAnyReport(t *testing.T) {
	a := testutil.Demo(t, "vulnerable-all")
	outputs := map[string]*bytes.Buffer{"json": {}, "sarif": {}, "html": {}, "text": {}}
	if err := report.JSON(outputs["json"], a); err != nil {
		t.Fatal(err)
	}
	if err := report.SARIF(outputs["sarif"], a); err != nil {
		t.Fatal(err)
	}
	if err := report.HTML(outputs["html"], a); err != nil {
		t.Fatal(err)
	}
	report.Text(outputs["text"], a)
	for name, buf := range outputs {
		for _, s := range plantedSecrets {
			if strings.Contains(buf.String(), s) {
				t.Errorf("%s output leaks secret %q", name, s)
			}
		}
	}
}

func TestSARIFStructure(t *testing.T) {
	a := testutil.Demo(t, "vulnerable-all")
	var buf bytes.Buffer
	if err := report.SARIF(&buf, a); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				CodeFlows []json.RawMessage `json:"codeFlows"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %s %s", log.Version, log.Schema)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "CloudGraph" {
		t.Error("driver name")
	}
	ids := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		ids[r.ID] = true
	}
	flows := 0
	for _, r := range run.Results {
		if !ids[r.RuleID] {
			t.Errorf("result references undeclared rule %s", r.RuleID)
		}
		if r.Level != "error" && r.Level != "warning" && r.Level != "note" {
			t.Errorf("bad level %q", r.Level)
		}
		if len(r.Locations) == 0 || r.Locations[0].Physical.Artifact.URI == "" {
			t.Errorf("result %s has no location", r.RuleID)
		}
		if r.Locations[0].Physical.Region != nil && r.Locations[0].Physical.Region.StartLine < 1 {
			t.Errorf("startLine must be >= 1")
		}
		flows += len(r.CodeFlows)
	}
	if flows == 0 {
		t.Error("attack paths should be exported as codeFlows")
	}
	if len(run.Results) < len(a.Findings) {
		t.Errorf("results %d < findings %d", len(run.Results), len(a.Findings))
	}
}

func TestHTMLEscapesContent(t *testing.T) {
	a := testutil.Scan(t, "c.yml", "services:\n  \"<script>alert(1)</script>\":\n    image: nginx:latest\n    ports: [\"80:80\"]\n")
	var buf bytes.Buffer
	if err := report.HTML(&buf, a); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Error("report HTML must escape resource names")
	}
}
