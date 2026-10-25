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

type raw struct {
	nodes []string
	edges []*model.Edge
}

func traversable(e *model.Edge, visited map[string]bool) bool {
	return e.Attack && e.Confidence != model.Unknown && !visited[e.To]
}

// Find returns the best attack path per (first compromised resource, last hop,
// target) using the default limits.
func Find(g *graph.Graph) []*model.Path {
	ps, _ := FindWith(g, model.DefaultSearchLimits())
	return ps
}

// FindWith searches with explicit limits and reports where they cut the search.
//
// MaxPivots bounds how many network pivots a single path may contain: chains of
// several pivots through ordinary application tiers are the intended
// architecture, not a finding. MaxDepth and MaxCandidates only keep the search
// bounded; when they are reached the result is marked incomplete.
func FindWith(g *graph.Graph, lim model.SearchLimits) ([]*model.Path, model.PathSearch) {
	stats := model.PathSearch{Limits: lim}
	var found []raw
	visited := map[string]bool{graph.InternetID: true}
	var nodes = []string{graph.InternetID}
	var edges []*model.Edge
	lateral := 0

	var dfs func(id string)
	dfs = func(id string) {
		if len(found) >= lim.MaxCandidates {
			stats.CandidateLimitHit = true
			return
		}
		if len(edges) >= lim.MaxDepth {
			for _, e := range g.Out(id) {
				if traversable(e, visited) {
					stats.DepthLimitHits++
					break
				}
			}
			return
		}
		for _, e := range g.Out(id) {
			if !traversable(e, visited) {
				continue
			}
			isLateral := e.Type == "network_reach"
			if isLateral && lateral >= lim.MaxPivots {
				stats.PivotLimitHits++
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
				if len(found) >= lim.MaxCandidates {
					stats.CandidateLimitHit = true
				} else {
					found = append(found, raw{append([]string(nil), nodes...), append([]*model.Edge(nil), edges...)})
				}
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

	// Routes that share (compromised resource, last hop, target) are merged
	// into one path: the best supported route represents the group, the others
	// are counted and, when asked for, kept as alternatives.
	groups := map[string][]raw{}
	for _, p := range found {
		key := groupKey(g, p)
		groups[key] = append(groups[key], p)
	}
	type merged struct {
		path *model.Path
		alts []*model.Path
	}
	var all []merged
	for _, rs := range groups {
		sort.Slice(rs, func(i, j int) bool { return better(rs[i], rs[j]) })
		m := merged{path: build(g, rs[0])}
		m.path.SimilarRoutes = len(rs) - 1
		if lim.ShowAlternatives {
			for _, alt := range rs[1:min(len(rs), 1+model.MaxAlternatives)] {
				m.alts = append(m.alts, build(g, alt))
			}
		}
		all = append(all, m)
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i].path, all[j].path
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Signature < b.Signature
	})
	out := make([]*model.Path, len(all))
	for i, m := range all {
		m.path.ID = fmt.Sprintf("path-%d", i+1)
		for j, alt := range m.alts {
			alt.ID = fmt.Sprintf("%s-alt-%d", m.path.ID, j+1)
		}
		m.path.Alternatives = m.alts
		out[i] = m.path
	}
	stats.Candidates = len(found)
	stats.SearchComplete = !stats.CandidateLimitHit && stats.DepthLimitHits == 0
	stats.Complete = stats.SearchComplete
	stats.ScopeLimited = !stats.SearchComplete || stats.PivotLimitHits > 0
	stats.Coverage = coverageOf(g)
	stats.Notices = stats.BuildNotices()
	return out, stats
}

// coverageOf summarises what the search had to work with.
func coverageOf(g *graph.Graph) model.Coverage {
	c := model.Coverage{ResourceKinds: map[string]int{}, EdgeTypes: map[string]int{}}
	for _, r := range g.Resources {
		c.ResourceKinds[r.Kind]++
	}
	for _, e := range g.Edges {
		switch {
		case e.Confidence == model.Unknown:
			c.UnknownEdges++
		case e.Attack:
			c.EdgeTypes[e.Type]++
		}
	}
	return c
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

// weakSteps counts the steps that are not confirmed by the configuration.
func weakSteps(edges []*model.Edge) int {
	n := 0
	for _, e := range edges {
		if e.Confidence != model.Confirmed {
			n++
		}
	}
	return n
}

// better decides which of two routes to the same target represents the group.
// Evidence comes before brevity: a longer route whose weakest step is confirmed
// beats a shorter one that needs an extra assumption, because the reported path
// (and its score) should be the one best supported by the configuration.
func better(a, b raw) bool {
	if ra, rb := minRank(a.edges), minRank(b.edges); ra != rb {
		return ra > rb
	}
	if wa, wb := weakSteps(a.edges), weakSteps(b.edges); wa != wb {
		return wa < wb
	}
	if len(a.edges) != len(b.edges) {
		return len(a.edges) < len(b.edges)
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
