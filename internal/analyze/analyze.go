// Package analyze wires the pipeline together: parse → graph → rules → paths.
package analyze

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/TroubieD3v/cloudgraph/internal/graph"
	"github.com/TroubieD3v/cloudgraph/internal/mask"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
	"github.com/TroubieD3v/cloudgraph/internal/paths"
	"github.com/TroubieD3v/cloudgraph/internal/rules"
)

// Run imports the files and analyses them.
func Run(name string, files []parse.File) (*model.Analysis, *parse.Inventory, error) {
	inv, err := parse.Parse(files)
	if err != nil {
		return nil, nil, err
	}
	a := FromInventory(name, inv)
	for _, f := range files {
		a.Inputs = append(a.Inputs, f.Name)
	}
	return a, inv, nil
}

// FromInventory runs graph building, rules and path search.
func FromInventory(name string, inv *parse.Inventory) *model.Analysis {
	g := graph.Build(inv.Resources)
	findings, fixes := rules.Run(inv, g)
	ps := paths.Find(g)

	for _, p := range ps {
		inPath := map[string]bool{}
		for _, n := range p.Nodes {
			inPath[n] = true
		}
		for _, f := range findings {
			if inPath[f.ResourceID] {
				p.FindingIDs = append(p.FindingIDs, f.ID)
			}
		}
	}

	now := time.Now().UTC()
	sum := sha1.Sum([]byte(fmt.Sprintf("%s|%d", name, now.UnixNano())))
	a := &model.Analysis{
		ID:        "an-" + hex.EncodeToString(sum[:5]),
		Name:      name,
		CreatedAt: now.Format(time.RFC3339),
		Resources: g.Resources,
		Edges:     g.Edges,
		Findings:  findings,
		Paths:     ps,
		Unknowns:  g.Unknowns,
		Fixes:     fixes,
		Hotspots:  paths.Hotspots(ps),
		Warnings:  inv.Warnings,
	}
	a.Sources = map[string][]string{}
	for name, lines := range inv.Files {
		if len(lines) <= 20000 {
			a.Sources[name] = mask.Lines(lines)
		}
	}
	if a.Inputs == nil {
		a.Inputs = []string{}
	}
	a.ComputeSummary()
	return a
}

// InventoryOf rebuilds an inventory from a stored analysis. Nodes synthesised
// by the graph builder are dropped so that rebuilding does not duplicate them.
func InventoryOf(a *model.Analysis) (*parse.Inventory, error) {
	var res []*model.Resource
	for _, r := range a.Resources {
		if !r.Generated {
			res = append(res, r)
		}
	}
	cp, err := cloneResources(res)
	if err != nil {
		return nil, err
	}
	return &parse.Inventory{Resources: cp, Files: map[string][]string{}}, nil
}

func cloneResources(rs []*model.Resource) ([]*model.Resource, error) {
	b, err := json.Marshal(rs)
	if err != nil {
		return nil, err
	}
	var out []*model.Resource
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
