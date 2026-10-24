package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// EscapeReason explains why a workload can break out to its host.
type EscapeReason struct {
	Text string
	Line int
}

// EscapeReasons lists the reasons a compromised workload could reach the host.
func EscapeReasons(r *model.Resource) []EscapeReason {
	w := r.Workload
	if w == nil {
		return nil
	}
	mounted := map[string]bool{}
	for _, c := range w.Containers {
		for _, m := range c.Mounts {
			mounted[m] = true
		}
	}
	var out []EscapeReason
	for _, c := range w.Containers {
		if model.Bool(c.Privileged, false) {
			l := c.Locs["privileged"]
			if l == 0 {
				l = c.Locs["_"]
			}
			out = append(out, EscapeReason{fmt.Sprintf("container %q is privileged", c.Name), l})
		}
		if caps := model.EscapeCaps(c.CapAdd); len(caps) > 0 {
			l := c.Locs["capabilities"]
			if l == 0 {
				l = c.Locs["cap_add"]
			}
			if l == 0 {
				l = c.Locs["_"]
			}
			out = append(out, EscapeReason{fmt.Sprintf("container %q adds capabilities %s", c.Name, strings.Join(caps, ", ")), l})
		}
		if w.HostPID && (model.Bool(c.Privileged, false) || model.Has(model.DangerousCaps(c.CapAdd), "SYS_PTRACE", "SYS_ADMIN")) {
			out = append(out, EscapeReason{fmt.Sprintf("hostPID combined with ptrace-capable container %q", c.Name), w.Locs["hostPID"]})
		}
	}
	for _, v := range w.Volumes {
		if !mounted[v.Name] && r.Domain == model.DomainKubernetes {
			continue
		}
		switch v.Kind {
		case "socket":
			out = append(out, EscapeReason{fmt.Sprintf("mounts container runtime socket %s", v.Source), v.Line})
		case "hostPath", "bind":
			if model.RiskyHostPath(v.Source) {
				out = append(out, EscapeReason{fmt.Sprintf("mounts sensitive host path %s", v.Source), v.Line})
			}
		}
	}
	return out
}

// builtinRules approximates the default ClusterRoles shipped with Kubernetes.
func builtinRules(name string) ([]model.PolicyRule, bool) {
	switch name {
	case "cluster-admin":
		return []model.PolicyRule{{Resources: []string{"*"}, Verbs: []string{"*"}}}, true
	case "admin", "edit":
		return []model.PolicyRule{
			{Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}},
			{Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
			{Resources: []string{"pods"}, Verbs: []string{"create"}},
		}, true
	case "view":
		return nil, true
	}
	return nil, false
}

type capDef struct {
	key, name string
	weight    int
	reason    string
}

func capFor(rule model.PolicyRule) []capDef {
	var out []capDef
	if model.Has(rule.Resources, "*") && model.Has(rule.Verbs, "*") && len(rule.ResourceNames) == 0 {
		return []capDef{{"admin", "Full control of Kubernetes API", 100, "wildcard permissions on all resources"}}
	}
	secretsRes := model.Has(rule.Resources, "secrets")
	if secretsRes && model.Has(rule.Verbs, "get", "list", "watch") && len(rule.ResourceNames) == 0 {
		out = append(out, capDef{"secrets-read", "Read Kubernetes Secrets", 85, "can read every Secret in scope"})
	}
	if model.Has(rule.Resources, "pods/exec", "pods/attach", "pods/*") && model.Has(rule.Verbs, "create", "get") {
		out = append(out, capDef{"pod-exec", "Exec into other pods", 62, "can run commands in other pods"})
	}
	if model.Has(rule.Resources, "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "replicasets") &&
		model.Has(rule.Verbs, "create") && len(rule.ResourceNames) == 0 {
		out = append(out, capDef{"workload-create", "Create workloads", 78, "can create pods that mount any ServiceAccount, Secret or host path"})
	}
	if model.Has(rule.Resources, "roles", "clusterroles", "rolebindings", "clusterrolebindings", "users", "groups", "serviceaccounts") &&
		model.HasExact(rule.Verbs, "escalate", "bind", "impersonate", "*") {
		out = append(out, capDef{"rbac-escalation", "RBAC privilege escalation", 90, "can grant itself or impersonate higher privileges"})
	}
	if model.HasExact(rule.Resources, "serviceaccounts/token") && model.Has(rule.Verbs, "create") {
		out = append(out, capDef{"rbac-escalation", "RBAC privilege escalation", 90, "can mint tokens for other ServiceAccounts"})
	}
	return out
}

type verdict int

const (
	vAllow verdict = iota
	vDeny
	vUnknown
)

// netpolVerdict decides if src can open connections to dst according to the
// NetworkPolicies present in the input.
func (g *Graph) netpolVerdict(src, dst *model.Resource) (verdict, string, []string) {
	selecting, unresolvable := g.selectingPolicies(dst)
	if unresolvable != nil {
		return vUnknown, fmt.Sprintf("NetworkPolicy %s uses selectors CloudGraph does not evaluate (matchExpressions)", unresolvable.Name), nil
	}
	if len(selecting) == 0 {
		return vAllow, fmt.Sprintf("no NetworkPolicy in namespace %q isolates %s (Kubernetes default is allow)", dst.Namespace, dst.Name),
			[]string{"The input contains every NetworkPolicy of the cluster"}
	}
	unknownMsg := ""
	for _, np := range selecting {
		for _, peer := range np.NetPol.AllowSources {
			if peer.AllowAll {
				return vAllow, fmt.Sprintf("NetworkPolicy %s allows all sources", np.Name), []string{"NetworkPolicy is enforced by the cluster CNI plugin"}
			}
			if !peer.HasPodSelector && !peer.HasNamespaceSel {
				if peer.IPBlock != "" {
					unknownMsg = fmt.Sprintf("NetworkPolicy %s allows ipBlock %s; pod IPs are not part of the input", np.Name, peer.IPBlock)
				}
				continue
			}
			nsOK := true
			if peer.HasNamespaceSel {
				switch {
				case len(peer.NamespaceSelector) == 0:
					nsOK = true
				case len(peer.NamespaceSelector) == 1 && peer.NamespaceSelector["kubernetes.io/metadata.name"] != "":
					nsOK = peer.NamespaceSelector["kubernetes.io/metadata.name"] == src.Namespace
				default:
					nsRes := g.byID[k8sNSID(src.Namespace)]
					if nsRes == nil {
						unknownMsg = fmt.Sprintf("NetworkPolicy %s selects namespaces by label but Namespace %q is not in the input", np.Name, src.Namespace)
						continue
					}
					nsOK = matchesLabelsAll(peer.NamespaceSelector, nsRes.Labels)
				}
			} else if src.Namespace != np.Namespace {
				nsOK = false
			}
			podOK := true
			if peer.HasPodSelector && len(peer.PodSelector) > 0 {
				podOK = matchesLabels(peer.PodSelector, src.Workload.PodLabels)
			}
			if nsOK && podOK {
				return vAllow, fmt.Sprintf("NetworkPolicy %s allows traffic from %s", np.Name, src.Name),
					[]string{"NetworkPolicy is enforced by the cluster CNI plugin"}
			}
		}
	}
	if unknownMsg != "" {
		return vUnknown, unknownMsg, nil
	}
	return vDeny, "", nil
}

// selectingPolicies returns the ingress NetworkPolicies that select dst. If a
// policy cannot be evaluated it is returned as the second value.
func (g *Graph) selectingPolicies(dst *model.Resource) ([]*model.Resource, *model.Resource) {
	var selecting []*model.Resource
	for _, r := range g.Resources {
		if r.Kind != model.KindNetworkPolicy || r.Namespace != dst.Namespace || r.NetPol == nil || !r.NetPol.Ingress {
			continue
		}
		if r.NetPol.Unresolvable {
			return nil, r
		}
		if len(r.NetPol.PodSelector) == 0 || matchesLabels(r.NetPol.PodSelector, dst.Workload.PodLabels) {
			selecting = append(selecting, r)
		}
	}
	return selecting, nil
}

// Isolated reports whether any ingress NetworkPolicy in the input selects the workload.
// Policies CloudGraph cannot evaluate count as isolating (benefit of the doubt).
func (g *Graph) Isolated(w *model.Resource) bool {
	sel, unresolvable := g.selectingPolicies(w)
	return len(sel) > 0 || unresolvable != nil
}

func matchesLabelsAll(sel, labels map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func k8sNSID(ns string) string { return "k8s:Namespace/" + ns }

func (g *Graph) buildKubernetes() {
	res := append([]*model.Resource(nil), g.Resources...)
	var wls []*model.Resource
	for _, r := range res {
		if r.Domain == model.DomainKubernetes && r.Kind == model.KindWorkload {
			wls = append(wls, r)
		}
	}
	if len(wls) == 0 && !hasKind(res, model.DomainKubernetes, model.KindIngress, model.KindBinding, model.KindService) {
		return
	}

	// Ingress and Service exposure
	for _, r := range res {
		if r.Domain != model.DomainKubernetes {
			continue
		}
		switch r.Kind {
		case model.KindIngress:
			label := "Internet reaches Ingress " + r.Name
			if len(r.Ingress.Hosts) > 0 {
				label += " (" + strings.Join(r.Ingress.Hosts, ", ") + ")"
			}
			conds := []string{"An ingress controller serves this Ingress and is reachable from the Internet"}
			if !r.Ingress.TLS {
				conds = append(conds, "Ingress has no TLS configured")
			}
			g.addEdge(edgeOpt{from: InternetID, to: r.ID, typ: "exposes", label: label, conf: model.Inferred, conds: conds,
				src: model.Source{File: r.Src.File, Line: r.Loc("spec"), Path: "spec"}, attack: true})
			for _, b := range r.Ingress.Backends {
				sid := fmt.Sprintf("k8s:Service/%s/%s", r.Namespace, b.Service)
				if g.byID[sid] != nil {
					g.addEdge(edgeOpt{from: r.ID, to: sid, typ: "routes_to", label: "Ingress routes to Service " + b.Service,
						conf: model.Confirmed, src: model.Source{File: r.Src.File, Line: b.Line}, attack: true})
				} else {
					g.unknown(r, fmt.Sprintf("Ingress %s routes to Service %q which is not defined in the input; no connection assumed", r.Name, b.Service),
						model.Source{File: r.Src.File, Line: b.Line})
				}
			}
		case model.KindService:
			if r.Service.Type == "LoadBalancer" || r.Service.Type == "NodePort" {
				g.addEdge(edgeOpt{from: InternetID, to: r.ID, typ: "exposes",
					label: fmt.Sprintf("Internet reaches %s Service %s", r.Service.Type, r.Name), conf: model.Inferred,
					conds: []string{"Cloud load balancer / node ports are reachable from the Internet"},
					src:   model.Source{File: r.Src.File, Line: r.Loc("type"), Path: "spec.type"}, attack: true})
			}
			if len(r.Service.Selector) == 0 {
				continue
			}
			matched := 0
			for _, w := range wls {
				if w.Namespace == r.Namespace && matchesLabels(r.Service.Selector, w.Workload.PodLabels) {
					matched++
					g.addEdge(edgeOpt{from: r.ID, to: w.ID, typ: "selects",
						label:    fmt.Sprintf("Service %s selects %s", r.Name, w.Name),
						conf:     model.Inferred,
						evidence: "selector " + fmtLabels(r.Service.Selector) + " matches pod labels " + fmtLabels(w.Workload.PodLabels),
						src:      r.Src, attack: true})
				}
			}
			if matched == 0 {
				g.unknown(r, fmt.Sprintf("Service %s selector %s matches no workload in the input; its backends are unknown", r.Name, fmtLabels(r.Service.Selector)), r.Src)
			}
		}
	}

	// Workload -> ServiceAccount, secrets, host escape
	saByID := map[string]*model.Resource{}
	for _, r := range res {
		if r.Domain == model.DomainKubernetes && r.Kind == model.KindServiceAccount {
			saByID[r.ID] = r
		}
	}
	for _, w := range wls {
		sid := fmt.Sprintf("k8s:ServiceAccount/%s/%s", w.Namespace, w.Workload.ServiceAccount)
		sa := saByID[sid]
		if sa == nil {
			sa = g.ensure(&model.Resource{ID: sid, Domain: model.DomainKubernetes, Kind: model.KindServiceAccount, Type: "ServiceAccount",
				Name: w.Workload.ServiceAccount, Namespace: w.Namespace, Src: w.Src, Attrs: map[string]any{"implicit": true}})
			saByID[sid] = sa
		}
		line := w.Workload.Locs["serviceAccountName"]
		if line == 0 {
			line = w.Workload.Locs["_podspec"]
		}
		src := model.Source{File: w.Src.File, Line: line, Path: "spec.serviceAccountName"}
		if model.EffectiveAutomount(w.Workload, sa.AutomountSA) {
			g.addEdge(edgeOpt{from: w.ID, to: sid, typ: "runs_as",
				label: fmt.Sprintf("%s runs as ServiceAccount %s and receives its API token", w.Name, sa.Name),
				conf:  model.Conditional,
				conds: []string{conditionCompromise, "ServiceAccount token is mounted into the pod (automountServiceAccountToken is not false)"},
				src:   src, attack: true})
		} else {
			g.addEdge(edgeOpt{from: w.ID, to: sid, typ: "runs_as", label: w.Name + " runs as ServiceAccount " + sa.Name + " (token not mounted)",
				conf: model.Confirmed, src: src})
		}

		// Secrets (structural: blast radius of the workload itself)
		for _, c := range w.Workload.Containers {
			names := append([]string(nil), c.EnvFromSecrets...)
			for _, e := range c.Env {
				if e.SecretRef != "" {
					names = append(names, e.SecretRef)
				}
			}
			for _, v := range w.Workload.Volumes {
				if v.Kind == "secret" && mountedBy(c, v.Name) {
					names = append(names, v.Source)
				}
			}
			for _, n := range mergeStrings(nil, names...) {
				secID := fmt.Sprintf("k8s:Secret/%s/%s", w.Namespace, n)
				if g.byID[secID] != nil {
					g.addEdge(edgeOpt{from: w.ID, to: secID, typ: "uses_secret", label: w.Name + " consumes Secret " + n,
						conf: model.Confirmed, src: model.Source{File: w.Src.File, Line: c.Locs["_"]}})
				} else {
					g.unknown(w, fmt.Sprintf("%s references Secret %q which is not in the input (it may be created elsewhere)", w.Name, n),
						model.Source{File: w.Src.File, Line: c.Locs["_"]})
				}
			}
		}

		// Host escape
		if reasons := EscapeReasons(w); len(reasons) > 0 {
			host := g.ensure(&model.Resource{ID: "k8s:Node/host", Domain: model.DomainKubernetes, Kind: model.KindHost, Type: "Node",
				Name: "Kubernetes node (host)", Sensitive: true, SensitiveReason: "Node takeover exposes kubelet credentials and every pod on the node"})
			var texts []string
			for _, rs := range reasons {
				texts = append(texts, rs.Text)
			}
			g.addEdge(edgeOpt{from: w.ID, to: host.ID, typ: "escape",
				label: fmt.Sprintf("%s can escape to the node", w.Name), conf: model.Conditional,
				conds:    []string{conditionCompromise, "Container isolation is bypassed: " + strings.Join(texts, "; ")},
				evidence: strings.Join(texts, "; "),
				src:      model.Source{File: w.Src.File, Line: reasons[0].Line}, attack: true})
		}
	}

	// Bindings -> capabilities
	for _, b := range res {
		if b.Domain != model.DomainKubernetes || b.Kind != model.KindBinding {
			continue
		}
		g.bindingEdges(b, saByID)
	}

	// Lateral movement to pivot-worthy workloads; repeat until stable.
	for pass := 0; pass < 4; pass++ {
		before := len(g.Edges)
		g.k8sLateral(wls)
		if len(g.Edges) == before {
			break
		}
	}
}

func (g *Graph) k8sLateral(wls []*model.Resource) {
	unk := map[string][]string{}
	unkDst := map[string]*model.Resource{}
	defer func() {
		keys := make([]string, 0, len(unk))
		for k := range unk {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dst := unkDst[k]
			ev := k[strings.Index(k, "|")+1:]
			g.unknown(dst, fmt.Sprintf("Cannot decide whether %s can reach %s: %s", strings.Join(unk[k], ", "), dst.Name, ev), dst.Src)
		}
	}()
	for _, dst := range wls {
		if !g.pivot(dst) {
			continue
		}
		for _, src := range wls {
			if src.ID == dst.ID {
				continue
			}
			v, ev, conds := g.netpolVerdict(src, dst)
			switch v {
			case vAllow:
				g.addEdge(edgeOpt{from: src.ID, to: dst.ID, typ: "network_reach",
					label:    fmt.Sprintf("%s can open connections to %s", src.Name, dst.Name),
					conf:     model.Conditional,
					conds:    append([]string{conditionCompromise}, conds...),
					evidence: ev, src: dst.Src, attack: true})
			case vUnknown:
				unk[dst.ID+"|"+ev] = append(unk[dst.ID+"|"+ev], src.Name)
				unkDst[dst.ID+"|"+ev] = dst
			}
		}
	}
}

func mountedBy(c model.Container, vol string) bool {
	for _, m := range c.Mounts {
		if m == vol {
			return true
		}
	}
	return false
}

func hasKind(res []*model.Resource, domain string, kinds ...string) bool {
	for _, r := range res {
		if r.Domain != domain {
			continue
		}
		for _, k := range kinds {
			if r.Kind == k {
				return true
			}
		}
	}
	return false
}

func fmtLabels(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (g *Graph) bindingEdges(b *model.Resource, saByID map[string]*model.Resource) {
	spec := b.Binding
	// Resolve the referenced role.
	var role *model.Resource
	var rules []model.PolicyRule
	roleID := ""
	switch spec.RoleKind {
	case "Role":
		roleID = fmt.Sprintf("k8s:Role/%s/%s", b.Namespace, spec.RoleName)
	default:
		roleID = "k8s:ClusterRole/" + spec.RoleName
	}
	role = g.byID[roleID]
	roleSrc := model.Source{File: b.Src.File, Line: b.Loc("roleRef"), Path: "roleRef"}
	switch {
	case role != nil:
		rules = role.Rules
		if role.Attrs["aggregated"] == true {
			g.unknown(role, fmt.Sprintf("ClusterRole %s uses an aggregationRule; aggregated permissions are not evaluated", role.Name), role.Src)
		}
		g.addEdge(edgeOpt{from: b.ID, to: role.ID, typ: "role_ref", label: "binding references " + spec.RoleKind + " " + role.Name,
			conf: model.Confirmed, src: roleSrc})
	default:
		if br, ok := builtinRules(spec.RoleName); ok && spec.RoleKind != "Role" {
			rules = br
		} else {
			g.unknown(b, fmt.Sprintf("%s %s references %s %q which is not in the input; its permissions are unknown", b.Type, b.Name, spec.RoleKind, spec.RoleName), roleSrc)
			return
		}
	}

	scopeNS := ""
	if !spec.Cluster {
		scopeNS = b.Namespace
	}
	scope := model.Scope(scopeNS)

	// Which subjects does this binding give permissions to?
	type grantee struct {
		id    string
		label string
		conf  model.Confidence
		conds []string
		inet  bool
	}
	var grantees []grantee
	for _, s := range spec.Subjects {
		switch s.Kind {
		case "ServiceAccount":
			id := fmt.Sprintf("k8s:ServiceAccount/%s/%s", s.Namespace, s.Name)
			if saByID[id] != nil {
				grantees = append(grantees, grantee{id: id, label: fmt.Sprintf("ServiceAccount %s is bound by %s", s.Name, b.Name), conf: model.Confirmed})
			}
		case "Group":
			switch {
			case s.Name == "system:unauthenticated":
				grantees = append(grantees, grantee{id: InternetID, label: "Anonymous (unauthenticated) users are bound by " + b.Name, conf: model.Confirmed, inet: true,
					conds: []string{"API server is reachable and anonymous auth is enabled"}})
			case s.Name == "system:serviceaccounts" || strings.HasPrefix(s.Name, "system:serviceaccounts:"):
				nsFilter := strings.TrimPrefix(strings.TrimPrefix(s.Name, "system:serviceaccounts"), ":")
				for id, sa := range saByID {
					if nsFilter == "" || sa.Namespace == nsFilter {
						grantees = append(grantees, grantee{id: id, label: fmt.Sprintf("ServiceAccount %s is bound by %s via group %s", sa.Name, b.Name, s.Name), conf: model.Confirmed})
					}
				}
			}
		}
	}
	sort.Slice(grantees, func(i, j int) bool { return grantees[i].id < grantees[j].id })
	if len(grantees) == 0 {
		return
	}

	type grant struct {
		def  capDef
		line int
		rule string
	}
	var grants []grant
	secretEdges := map[string]int{}
	for _, rule := range rules {
		for _, c := range capFor(rule) {
			grants = append(grants, grant{c, rule.Line, describeRule(rule)})
		}
		if model.Has(rule.Resources, "secrets") && model.Has(rule.Verbs, "get", "list", "watch") && len(rule.ResourceNames) > 0 {
			for _, n := range rule.ResourceNames {
				secretEdges[n] = rule.Line
			}
		}
	}
	for _, gr := range grants {
		capID := fmt.Sprintf("cap:k8s:%s:%s", gr.def.key, scope)
		capName := fmt.Sprintf("%s (%s)", gr.def.name, scopeLabel(scopeNS))
		node := g.ensure(&model.Resource{ID: capID, Domain: model.DomainKubernetes, Kind: model.KindCapability, Type: "Capability",
			Name: capName, Namespace: scopeNS, Sensitive: true, SensitiveReason: gr.def.reason,
			Attrs: map[string]any{"weight": gr.def.weight, "capability": gr.def.key, "scope": scope}})
		if gr.def.key == "secrets-read" {
			if scopeNS == "" {
				node.Attrs["weight"] = 92
			}
			var names []string
			for _, r := range g.Resources {
				if r.Domain == model.DomainKubernetes && r.Kind == model.KindSecret && (scopeNS == "" || r.Namespace == scopeNS) {
					names = append(names, r.Namespace+"/"+r.Name)
				}
			}
			sort.Strings(names)
			node.Attrs["secretsInInput"] = names
		}
		line := gr.line
		if line == 0 {
			line = b.Loc("roleRef")
		}
		file := b.Src.File
		if role != nil {
			file = role.Src.File
		}
		g.addEdge(edgeOpt{from: b.ID, to: capID, typ: "grants",
			label:    fmt.Sprintf("%s grants: %s", b.Name, gr.def.reason),
			conf:     model.Confirmed,
			evidence: gr.rule, src: model.Source{File: file, Line: line, Path: "rules"}, attack: true, discrim: gr.def.key})
	}
	for name, line := range secretEdges {
		sid := fmt.Sprintf("k8s:Secret/%s/%s", scopeOrBinding(scopeNS, b), name)
		if g.byID[sid] != nil {
			file := b.Src.File
			if role != nil {
				file = role.Src.File
			}
			g.addEdge(edgeOpt{from: b.ID, to: sid, typ: "reads_secret", label: fmt.Sprintf("%s may read Secret %s", b.Name, name),
				conf: model.Confirmed, src: model.Source{File: file, Line: line}, attack: true})
		}
	}
	for _, gt := range grantees {
		g.addEdge(edgeOpt{from: gt.id, to: b.ID, typ: "bound_by", label: gt.label, conf: gt.conf,
			conds: gt.conds, src: model.Source{File: b.Src.File, Line: b.Loc("subjects"), Path: "subjects"}, attack: true})
	}
}

func scopeOrBinding(scopeNS string, b *model.Resource) string {
	if scopeNS != "" {
		return scopeNS
	}
	return "default"
}

func scopeLabel(ns string) string {
	if ns == "" {
		return "cluster-wide"
	}
	return "namespace " + ns
}

func describeRule(r model.PolicyRule) string {
	return fmt.Sprintf("resources=[%s] verbs=[%s]", strings.Join(r.Resources, ","), strings.Join(r.Verbs, ","))
}
