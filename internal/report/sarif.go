// Package report renders an analysis as text, JSON, SARIF 2.1.0 or HTML.
package report

import (
	"encoding/json"
	"io"

	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/rules"
)

// Version is stamped into SARIF output; set by the main package.
var Version = "0.1.0"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Help             sarifText      `json:"help"`
	DefaultConfig    map[string]any `json:"defaultConfiguration"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifText         `json:"message"`
	Locations    []sarifLocation   `json:"locations,omitempty"`
	CodeFlows    []sarifCodeFlow   `json:"codeFlows,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`
	Fingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
	Message  *sarifText    `json:"message,omitempty"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
	Region   *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifFlowLocation `json:"locations"`
}

type sarifFlowLocation struct {
	Location sarifLocation `json:"location"`
}

func sarifLevel(sev string) string {
	switch sev {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	}
	return "note"
}

func securitySeverity(sev string) string {
	switch sev {
	case model.SevCritical:
		return "9.5"
	case model.SevHigh:
		return "8.0"
	case model.SevMedium:
		return "5.5"
	case model.SevLow:
		return "3.0"
	}
	return "0.5"
}

func loc(src model.Source, msg string) sarifLocation {
	l := sarifLocation{Physical: sarifPhysical{Artifact: sarifArtifact{URI: src.File, URIBaseID: "%SRCROOT%"}}}
	if src.Line > 0 {
		l.Physical.Region = &sarifRegion{StartLine: src.Line}
	}
	if msg != "" {
		l.Message = &sarifText{Text: msg}
	}
	return l
}

// SARIF writes a SARIF 2.1.0 log suitable for GitHub Code Scanning.
func SARIF(w io.Writer, a *model.Analysis) error {
	driver := sarifDriver{Name: "CloudGraph", Version: Version}
	for _, r := range rules.All() {
		driver.Rules = append(driver.Rules, sarifRule{
			ID: r.ID, Name: r.Title, ShortDescription: sarifText{r.Title}, Help: sarifText{r.Remediation},
			DefaultConfig: map[string]any{"level": sarifLevel(r.Severity)},
			Properties:    map[string]any{"tags": []string{"security", r.Domain}, "security-severity": securitySeverity(r.Severity)},
		})
	}
	driver.Rules = append(driver.Rules, sarifRule{
		ID: "CG-PATH", Name: "Potential attack path",
		ShortDescription: sarifText{"A chain of weaknesses may let an attacker move from an exposed entry point to a sensitive target"},
		Help:             sarifText{"Break the chain by fixing any step; use `cloudgraph simulate` to see which fixes remove the most paths."},
		DefaultConfig:    map[string]any{"level": "warning"},
		Properties:       map[string]any{"tags": []string{"security", "attack-path"}, "security-severity": "7.0"},
	})

	res := make([]sarifResult, 0, len(a.Findings)+len(a.Paths))
	for _, f := range a.Findings {
		res = append(res, sarifResult{
			RuleID: f.RuleID, Level: sarifLevel(f.Severity), Message: sarifText{f.Message + " — " + f.Remediation},
			Locations:    []sarifLocation{loc(f.Src, "")},
			Properties:   map[string]any{"resource": f.ResourceID, "severity": f.Severity},
			Fingerprints: map[string]string{"cloudgraph/v1": f.ID},
		})
	}
	for _, p := range a.Paths {
		r := sarifResult{
			RuleID: "CG-PATH", Level: sarifLevel(p.Severity),
			Message:      sarifText{"Potential attack path (" + string(p.Confidence) + ", score " + itoa(p.Score) + "): " + p.Title},
			Properties:   map[string]any{"score": p.Score, "severity": p.Severity, "prerequisites": p.Prerequisites, "confidence": p.Confidence},
			Fingerprints: map[string]string{"cloudgraph/v1": p.Signature},
		}
		var flow sarifThreadFlow
		for _, s := range p.Steps {
			if s.Src.File == "" {
				continue
			}
			flow.Locations = append(flow.Locations, sarifFlowLocation{Location: loc(s.Src, s.Label)})
		}
		if len(flow.Locations) > 0 {
			r.Locations = []sarifLocation{flow.Locations[len(flow.Locations)-1].Location}
			r.CodeFlows = []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{flow}}}
			res = append(res, r)
		}
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: res}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
