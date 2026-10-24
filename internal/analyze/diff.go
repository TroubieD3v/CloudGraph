package analyze

import (
	"sort"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// DiffResult describes how infrastructure state B differs from state A.
type DiffResult struct {
	ANameID          string            `json:"aName"`
	BNameID          string            `json:"bName"`
	ResourcesAdded   []string          `json:"resourcesAdded"`
	ResourcesRemoved []string          `json:"resourcesRemoved"`
	EdgesAdded       []*model.Edge     `json:"edgesAdded"`
	EdgesRemoved     []*model.Edge     `json:"edgesRemoved"`
	FindingsAdded    []*model.Finding  `json:"findingsAdded"`
	FindingsRemoved  []*model.Finding  `json:"findingsRemoved"`
	PathsAppeared    []*model.Path     `json:"pathsAppeared"`
	PathsDisappeared []*model.Path     `json:"pathsDisappeared"`
	Counts           map[string][2]int `json:"counts"` // metric -> [A, B]
}

// Diff compares two analyses by stable identifiers (resource IDs, edge IDs,
// finding IDs and path signatures), not by raw counts.
func Diff(a, b *model.Analysis) *DiffResult {
	d := &DiffResult{ANameID: a.Name, BNameID: b.Name,
		ResourcesAdded: []string{}, ResourcesRemoved: []string{}, EdgesAdded: []*model.Edge{}, EdgesRemoved: []*model.Edge{},
		FindingsAdded: []*model.Finding{}, FindingsRemoved: []*model.Finding{}, PathsAppeared: []*model.Path{}, PathsDisappeared: []*model.Path{},
		Counts: map[string][2]int{
			"resources": {len(a.Resources), len(b.Resources)},
			"edges":     {len(a.Edges), len(b.Edges)},
			"findings":  {len(a.Findings), len(b.Findings)},
			"paths":     {len(a.Paths), len(b.Paths)},
			"unknowns":  {len(a.Unknowns), len(b.Unknowns)},
		}}
	ra, rb := map[string]bool{}, map[string]bool{}
	for _, r := range a.Resources {
		ra[r.ID] = true
	}
	for _, r := range b.Resources {
		rb[r.ID] = true
	}
	for id := range rb {
		if !ra[id] {
			d.ResourcesAdded = append(d.ResourcesAdded, id)
		}
	}
	for id := range ra {
		if !rb[id] {
			d.ResourcesRemoved = append(d.ResourcesRemoved, id)
		}
	}
	sort.Strings(d.ResourcesAdded)
	sort.Strings(d.ResourcesRemoved)

	ea, eb := map[string]bool{}, map[string]bool{}
	for _, e := range a.Edges {
		ea[e.ID] = true
	}
	for _, e := range b.Edges {
		eb[e.ID] = true
	}
	for _, e := range b.Edges {
		if !ea[e.ID] {
			d.EdgesAdded = append(d.EdgesAdded, e)
		}
	}
	for _, e := range a.Edges {
		if !eb[e.ID] {
			d.EdgesRemoved = append(d.EdgesRemoved, e)
		}
	}

	fa, fb := map[string]bool{}, map[string]bool{}
	for _, f := range a.Findings {
		fa[f.ID] = true
	}
	for _, f := range b.Findings {
		fb[f.ID] = true
	}
	for _, f := range b.Findings {
		if !fa[f.ID] {
			d.FindingsAdded = append(d.FindingsAdded, f)
		}
	}
	for _, f := range a.Findings {
		if !fb[f.ID] {
			d.FindingsRemoved = append(d.FindingsRemoved, f)
		}
	}

	pa, pb := map[string]bool{}, map[string]bool{}
	for _, p := range a.Paths {
		pa[p.Signature] = true
	}
	for _, p := range b.Paths {
		pb[p.Signature] = true
	}
	for _, p := range b.Paths {
		if !pa[p.Signature] {
			d.PathsAppeared = append(d.PathsAppeared, p)
		}
	}
	for _, p := range a.Paths {
		if !pb[p.Signature] {
			d.PathsDisappeared = append(d.PathsDisappeared, p)
		}
	}
	return d
}
