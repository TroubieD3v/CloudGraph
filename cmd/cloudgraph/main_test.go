package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanExitCodes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.sarif")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"vulnerable config fails the gate", []string{"demo:vulnerable-all", "--fail-on", "high", "--format", "sarif", "--output", out}, 1},
		{"hardened config passes the gate", []string{"demo:hardened-infrastructure", "--fail-on", "low", "--format", "json", "--output", out}, 0},
		{"no gate requested", []string{"demo:vulnerable-all", "--format", "json", "--output", out}, 0},
		{"truncated search with --fail-incomplete", []string{"demo:insecure-kubernetes", "--max-depth", "3", "--fail-incomplete", "--format", "json", "--output", out}, 1},
		{"complete search with --fail-incomplete", []string{"demo:insecure-kubernetes", "--fail-incomplete", "--format", "json", "--output", out}, 0},
		{"invalid limit", []string{"demo:insecure-kubernetes", "--max-depth", "0", "--output", out}, 2},
		{"unknown severity", []string{"demo:insecure-kubernetes", "--fail-on", "urgent", "--output", out}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _ := cmdScan(c.args)
			if code != c.want {
				t.Errorf("exit code %d, want %d", code, c.want)
			}
		})
	}
}

func TestVulnerableSARIFHasFindingsAndPaths(t *testing.T) {
	out := filepath.Join(t.TempDir(), "vulnerable.sarif")
	if code, err := cmdScan([]string{"demo:vulnerable-all", "--format", "sarif", "--output", out}); code != 0 || err != nil {
		t.Fatalf("scan: %d %v", code, err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string            `json:"ruleId"`
				CodeFlows []json.RawMessage `json:"codeFlows"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatal(err)
	}
	findings, paths := 0, 0
	for _, r := range log.Runs[0].Results {
		if r.RuleID == "CG-PATH" && len(r.CodeFlows) > 0 {
			paths++
		} else {
			findings++
		}
	}
	if findings < 50 || paths < 10 {
		t.Errorf("vulnerable demo SARIF too thin: %d findings, %d paths", findings, paths)
	}
}
