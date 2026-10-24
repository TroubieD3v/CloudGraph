// Package paths searches the graph for conditional attack paths: chains from
// an externally reachable entry point to a sensitive target. A path is never
// proof of exploitation; every step lists the conditions it relies on.
package paths

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/graph"
	"github.com/TroubieD3v/cloudgraph/internal/model"
)

const (
	maxDepth = 10
	maxRaw   = 20000
	// maxLateral bounds how many network pivots a single path may contain.
	// Chains of several pivots through ordinary application tiers are the
	// intended architecture, not a finding.
	maxLateral = 1
)

type raw struct {
	nodes []string
	edges []*model.Edge
}

// Find returns the best attack path per (first compromised resource, target).
func Find(g *graph.Graph) []*model.Path {
	var found []raw
	visited := map[string]bool{graph.InternetID: true}
	var nodes = []string{graph.InternetID}
	var edges []*model.Edge
	lateral := 0

	var dfs func(id string)
	dfs = func(id string) {
		if len(found) >= maxRaw || len(edges) >= maxDepth {
			return
		}
		for _, e := range g.Out(id) {
			if !e.Attack || e.Confidence == model.Unknown || visited[e.To] {
				continue
			}
			isLateral := e.Type == "network_reach"
			if isLateral && lateral >= maxLateral {
				continue
			}
			to := g.Resource(e.To)
			if to == nil {
				continue
			}
			nodes = append(nodes, e.To)
			edges = append(edges, e)
			if isLateral {
				lateral++
			}
			if to.Sensitive {
				found = append(found, raw{append([]string(nil), nodes...), append([]*model.Edge(nil), edges...)})
			} else {
				visited[e.To] = true
				dfs(e.To)
				visited[e.To] = false
			}
			if isLateral {
				lateral--
			}
			nodes = nodes[:len(nodes)-1]
			edges = edges[:len(edges)-1]
		}
	}
	dfs(graph.InternetID)

	// Keep the best candidate per (compromised resource, target).
	best := map[string]raw{}
	for _, p := range found {
		key := groupKey(g, p)
		if cur, ok := best[key]; !ok || better(p, cur) {
			best[key] = p
		}
	}
	var out []*model.Path
	for _, p := range best {
		out = append(out, build(g, p))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Signature < out[j].Signature
	})
	for i, p := range out {
		p.ID = fmt.Sprintf("path-%d", i+1)
	}
	return out
}

func groupKey(g *graph.Graph, p raw) string {
	entry := p.nodes[1]
	for _, id := range p.nodes[1:] {
		switch g.Resource(id).Kind {
		case model.KindWorkload, model.KindInstance, model.KindDatabase, model.KindBucket:
			entry = id
			goto done
		}
	}
done:
	// The node just before the target keeps genuinely different routes
	// (e.g. via two different pivots) apart.
	prev := p.nodes[len(p.nodes)-2]
	return entry + "=>" + prev + "=>" + p.nodes[len(p.nodes)-1]
}

func minRank(edges []*model.Edge) int {
	m := 99
	for _, e := range edges {
		if r := e.Confidence.Rank(); r < m {
			m = r
		}
	}
	return m
}

func better(a, b raw) bool {
	if len(a.edges) != len(b.edges) {
		return len(a.edges) < len(b.edges)
	}
	if ra, rb := minRank(a.edges), minRank(b.edges); ra != rb {
		return ra > rb
	}
	return strings.Join(a.nodes, "|") < strings.Join(b.nodes, "|")
}

// TargetWeight returns the base impact of reaching a sensitive node.
func TargetWeight(r *model.Resource) int {
	switch v := r.Attrs["weight"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	switch r.Kind {
	case model.KindHost:
		return 100
	case model.KindDatabase:
		return 80
	case model.KindWorkload:
		return 75
	case model.KindBucket:
		return 60
	}
	return 50
}

func confFactor(c model.Confidence) float64 {
	switch c {
	case model.Confirmed:
		return 1.0
	case model.Inferred:
		return 0.92
	}
	return 0.85
}

func severityOf(score int) string {
	switch {
	case score >= 85:
		return model.SevCritical
	case score >= 70:
		return model.SevHigh
	case score >= 50:
		return model.SevMedium
	}
	return model.SevLow
}

func build(g *graph.Graph, p raw) *model.Path {
	target := g.Resource(p.nodes[len(p.nodes)-1])
	conf := model.Confirmed
	rank := minRank(p.edges)
	switch rank {
	case 2:
		conf = model.Inferred
	case 1:
		conf = model.Conditional
	}
	score := int(float64(TargetWeight(target))*confFactor(conf) + 0.5)
	if extra := len(p.edges) - 5; extra > 0 {
		score -= 2 * extra
	}
	if score < 1 {
		score = 1
	}

	path := &model.Path{
		Entry: p.nodes[0], Target: target.ID, Nodes: p.nodes, Confidence: conf, Score: score, Severity: severityOf(score),
		Signature: strings.Join(p.nodes, ">"),
	}
	seenCond := map[string]bool{}
	var expl []string
	for i, e := range p.edges {
		path.Steps = append(path.Steps, model.Step{
			From: e.From, To: e.To, EdgeID: e.ID, Label: e.Label, Confidence: e.Confidence,
			Conditions: e.Conditions, Evidence: e.Evidence, Src: e.Src,
		})
		for _, c := range e.Conditions {
			if !seenCond[c] {
				seenCond[c] = true
				path.Prerequisites = append(path.Prerequisites, c)
			}
		}
		line := fmt.Sprintf("%d. %s", i+1, e.Label)
		if e.Evidence != "" {
			line += " — " + e.Evidence
		}
		expl = append(expl, line)
	}

	first := p.nodes[1]
	for _, id := range p.nodes[1:] {
		switch g.Resource(id).Kind {
		case model.KindWorkload, model.KindInstance, model.KindDatabase, model.KindBucket:
			first = id
			goto named
		}
	}
named:
	if first == target.ID {
		path.Title = fmt.Sprintf("Internet exposes %s", target.Name)
	} else {
		path.Title = fmt.Sprintf("%s → %s", g.Resource(first).Name, target.Name)
	}
	path.Explanation = "Potential attack path derived from static configuration; it does not prove the application can actually be compromised.\n" +
		strings.Join(expl, "\n")
	return path
}

// Hotspots counts the paths each resource participates in (excluding the
// Internet node and the targets themselves) and returns those used by several.
func Hotspots(ps []*model.Path) []*model.Hotspot {
	counts := map[string]int{}
	for _, p := range ps {
		for _, id := range p.Nodes[1 : len(p.Nodes)-1] {
			counts[id]++
		}
	}
	var out []*model.Hotspot
	for id, n := range counts {
		if n >= 2 {
			out = append(out, &model.Hotspot{ResourceID: id, Paths: n})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Paths != out[j].Paths {
			return out[i].Paths > out[j].Paths
		}
		return out[i].ResourceID < out[j].ResourceID
	})
	return out
}
