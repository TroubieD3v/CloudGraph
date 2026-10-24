package graph

import (
	"fmt"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

func PortIsAllInterfaces(addr string) bool {
	return addr == "" || addr == "0.0.0.0" || addr == "::" || addr == "[::]"
}

func (g *Graph) buildCompose() {
	var svcs []*model.Resource
	for _, r := range g.Resources {
		if r.Domain == model.DomainCompose && r.Kind == model.KindWorkload {
			svcs = append(svcs, r)
		}
	}
	if len(svcs) == 0 {
		return
	}
	byName := map[string]*model.Resource{}
	for _, s := range svcs {
		byName[s.Name] = s
	}

	for _, s := range svcs {
		w := s.Workload

		// Published ports -> exposure
		for _, p := range w.Ports {
			if !PortIsAllInterfaces(p.BindAddr) {
				continue
			}
			host := "an ephemeral host port"
			if p.Host != 0 {
				host = fmt.Sprintf("host port %d", p.Host)
			}
			g.addEdge(edgeOpt{from: InternetID, to: s.ID, typ: "exposes", discrim: fmt.Sprint(p.Container),
				label:    fmt.Sprintf("Internet reaches %s via %s → container port %d", s.Name, host, p.Container),
				conf:     model.Confirmed,
				conds:    []string{"The Docker host is reachable from the Internet on this port (no host firewall)"},
				evidence: "port is published on all interfaces",
				src:      model.Source{File: s.Src.File, Line: p.Line, Path: "ports"}, attack: true})
		}
		if w.HostNetwork && len(w.Ports) == 0 {
			g.unknown(s, fmt.Sprintf("Service %s uses network_mode: host; the ports it listens on are not part of the configuration", s.Name),
				model.Source{File: s.Src.File, Line: w.Locs["network_mode"]})
		}

		// Networks (structural)
		for _, n := range w.Networks {
			nid := "compose:network/" + n
			if g.byID[nid] != nil {
				g.addEdge(edgeOpt{from: s.ID, to: nid, typ: "attached_to", label: s.Name + " attached to network " + n, conf: model.Confirmed, src: s.Src})
			}
		}

		// Secrets (structural)
		for _, c := range w.Containers {
			for _, sec := range c.EnvFromSecrets {
				sid := "compose:secret/" + sec
				if g.byID[sid] != nil {
					g.addEdge(edgeOpt{from: s.ID, to: sid, typ: "uses_secret", label: s.Name + " mounts secret " + sec, conf: model.Confirmed, src: s.Src})
				} else {
					g.unknown(s, fmt.Sprintf("%s uses secret %q which is not declared in this Compose project", s.Name, sec), s.Src)
				}
			}
		}

		// Escape to the Docker host
		if reasons := EscapeReasons(s); len(reasons) > 0 {
			host := g.ensure(&model.Resource{ID: "compose:host", Domain: model.DomainCompose, Kind: model.KindHost, Type: "DockerHost",
				Name: "Docker host", Sensitive: true, SensitiveReason: "Host takeover exposes every container, volume and secret on the machine"})
			var texts []string
			for _, rs := range reasons {
				texts = append(texts, rs.Text)
			}
			g.addEdge(edgeOpt{from: s.ID, to: host.ID, typ: "escape",
				label: fmt.Sprintf("%s can escape to the Docker host", s.Name), conf: model.Conditional,
				conds:    []string{conditionCompromise, "Container isolation is bypassed: " + strings.Join(texts, "; ")},
				evidence: strings.Join(texts, "; "),
				src:      model.Source{File: s.Src.File, Line: reasons[0].Line}, attack: true})
		}
	}

	// Service -> service relationships. Repeat until stable because a service
	// only becomes a pivot once its own onward edges exist.
	for pass := 0; pass < 4; pass++ {
		before := len(g.Edges)
		g.composeLateral(svcs)
		if len(g.Edges) == before {
			break
		}
	}
}

func (g *Graph) composeLateral(svcs []*model.Resource) {
	for _, a := range svcs {
		for _, b := range svcs {
			if a.ID == b.ID {
				continue
			}
			shared := sharedNetwork(a.Workload, b.Workload)
			dependsOn := contains(a.Workload.DependsOn, b.Name)
			refByEnv := referencesByEnv(a, b)
			hostNet := a.Workload.HostNetwork || b.Workload.HostNetwork

			switch {
			case (dependsOn || refByEnv) && (shared != "" || hostNet):
				why := "depends_on / links"
				conf := model.Confirmed
				if !dependsOn {
					why = "environment variable names the service as a hostname"
					conf = model.Inferred
				}
				g.addEdge(edgeOpt{from: a.ID, to: b.ID, typ: "connects_to", label: fmt.Sprintf("%s connects to %s", a.Name, b.Name),
					conf: conf, evidence: why, src: model.Source{File: a.Src.File, Line: a.Src.Line}})
				if g.pivot(b) {
					g.addEdge(edgeOpt{from: a.ID, to: b.ID, typ: "network_reach", label: fmt.Sprintf("%s can reach %s over the network", a.Name, b.Name),
						conf: model.Conditional, conds: []string{conditionCompromise, networkCond(shared, hostNet)},
						evidence: why, src: model.Source{File: a.Src.File, Line: a.Src.Line}, attack: true})
				}
			case g.pivot(b) && (shared != "" || hostNet):
				g.addEdge(edgeOpt{from: a.ID, to: b.ID, typ: "network_reach", label: fmt.Sprintf("%s can reach %s over the network", a.Name, b.Name),
					conf: model.Conditional, conds: []string{conditionCompromise, networkCond(shared, hostNet)},
					evidence: networkCond(shared, hostNet), src: model.Source{File: a.Src.File, Line: a.Src.Line}, attack: true})
			case g.pivot(b) && shared == "" && !hostNet && len(a.Workload.Networks) > 0 && len(b.Workload.Networks) > 0:
				// separate networks: deliberately no edge
			}
		}
	}
}

func networkCond(shared string, hostNet bool) string {
	if hostNet {
		return "A service uses host networking, so network isolation does not apply"
	}
	return fmt.Sprintf("Both services are attached to Docker network %q", shared)
}

func sharedNetwork(a, b *model.Workload) string {
	for _, x := range a.Networks {
		for _, y := range b.Networks {
			if x == y {
				return x
			}
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

// referencesByEnv reports whether an env value of a names b as host.
func referencesByEnv(a, b *model.Resource) bool {
	for _, c := range a.Workload.Containers {
		for _, e := range c.Env {
			if !e.Literal || e.LooksSecret {
				continue
			}
			v := e.Value
			if v == b.Name || strings.Contains(v, "://"+b.Name) || strings.Contains(v, "@"+b.Name+":") ||
				strings.HasPrefix(v, b.Name+":") || strings.Contains(v, "@"+b.Name+"/") {
				return true
			}
		}
	}
	return false
}
