// Package graph turns the resource inventory into a directed graph of
// relationships. Every edge records where it came from, how confident the
// engine is and which conditions must hold. Where the input is insufficient
// the builder emits an UnknownNote instead of inventing a connection.
package graph

import (
	"fmt"
	"sort"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// InternetID is the synthetic entry node for externally reachable resources.
const InternetID = "internet"

// Graph is the built relationship graph.
type Graph struct {
	Resources []*model.Resource
	Edges     []*model.Edge
	Unknowns  []*model.UnknownNote

	byID map[string]*model.Resource
	out  map[string][]*model.Edge
	seen map[string]bool
}

// Resource returns a node by ID.
func (g *Graph) Resource(id string) *model.Resource { return g.byID[id] }

// Out returns outgoing edges of a node.
func (g *Graph) Out(id string) []*model.Edge { return g.out[id] }

func (g *Graph) addResource(r *model.Resource) {
	if _, ok := g.byID[r.ID]; ok {
		return
	}
	g.byID[r.ID] = r
	g.Resources = append(g.Resources, r)
}

// ensure adds a synthetic node once and returns it.
func (g *Graph) ensure(r *model.Resource) *model.Resource {
	if ex, ok := g.byID[r.ID]; ok {
		return ex
	}
	if r.Domain == "" {
		r.Domain = model.DomainSynthetic
	}
	r.Generated = true
	g.addResource(r)
	return r
}

type edgeOpt struct {
	from, to string
	typ      string
	label    string
	conf     model.Confidence
	conds    []string
	evidence string
	src      model.Source
	attack   bool
	discrim  string // distinguishes parallel edges of the same type
}

func (g *Graph) addEdge(o edgeOpt) *model.Edge {
	id := fmt.Sprintf("%s>%s:%s", o.from, o.to, o.typ)
	if o.discrim != "" {
		id += ":" + o.discrim
	}
	if g.seen[id] {
		return nil
	}
	g.seen[id] = true
	e := &model.Edge{
		ID: id, From: o.from, To: o.to, Type: o.typ, Label: o.label, Confidence: o.conf,
		Conditions: o.conds, Evidence: o.evidence, Src: o.src, Attack: o.attack,
	}
	g.Edges = append(g.Edges, e)
	g.out[o.from] = append(g.out[o.from], e)
	return e
}

func (g *Graph) unknown(r *model.Resource, msg string, src model.Source) {
	for _, u := range g.Unknowns {
		if u.Message == msg {
			return
		}
	}
	id := fmt.Sprintf("u%d", len(g.Unknowns)+1)
	rid := ""
	if r != nil {
		rid = r.ID
	}
	g.Unknowns = append(g.Unknowns, &model.UnknownNote{ID: id, ResourceID: rid, Message: msg, Src: src})
}

// Build constructs the graph from resources.
func Build(resources []*model.Resource) *Graph {
	g := &Graph{
		byID: map[string]*model.Resource{},
		out:  map[string][]*model.Edge{},
		seen: map[string]bool{},
	}
	for _, r := range resources {
		g.addResource(r)
	}
	g.ensure(&model.Resource{
		ID: InternetID, Kind: model.KindInternet, Type: "Internet", Name: "Internet",
		Attrs: map[string]any{"description": "Untrusted external network"},
	})
	g.buildKubernetes()
	g.buildCompose()
	g.buildTerraform()

	sort.SliceStable(g.Resources, func(i, j int) bool { return g.Resources[i].ID < g.Resources[j].ID })
	sort.SliceStable(g.Edges, func(i, j int) bool { return g.Edges[i].ID < g.Edges[j].ID })
	return g
}

// conditionCompromise is attached to every edge that leaves a workload.
const conditionCompromise = "Attacker has code execution inside this workload (needs a separate application or supply-chain vulnerability)"

func matchesLabels(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if lv, ok := labels[k]; !ok || lv != v {
			return false
		}
	}
	return true
}

func mergeStrings(a []string, b ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// hasAttackOut reports whether compromising id would give an attacker at least
// one further step (token, escape, grant ...).
func (g *Graph) hasAttackOut(id string) bool {
	for _, e := range g.out[id] {
		if e.Attack && e.Confidence != model.Unknown {
			return true
		}
	}
	return false
}

// pivot reports whether lateral movement into r is worth modelling.
func (g *Graph) pivot(r *model.Resource) bool { return r.Sensitive || g.hasAttackOut(r.ID) }
