package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

// SimulationResult compares the analysis before and after virtual fixes.
type SimulationResult struct {
	Applied          []*model.Fix     `json:"applied"`
	Skipped          []string         `json:"skipped,omitempty"`
	PathsBefore      int              `json:"pathsBefore"`
	PathsAfter       int              `json:"pathsAfter"`
	PathsResolved    []*model.Path    `json:"pathsResolved"`
	PathsRemaining   []*model.Path    `json:"pathsRemaining"`
	PathsNew         []*model.Path    `json:"pathsNew"`
	FindingsBefore   int              `json:"findingsBefore"`
	FindingsAfter    int              `json:"findingsAfter"`
	FindingsResolved []*model.Finding `json:"findingsResolved"`
	After            *model.Analysis  `json:"after"`
}

func paramInt(p map[string]any, key string) int {
	switch v := p[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return -1
}

func paramStr(p map[string]any, key string) string {
	s, _ := p[key].(string)
	return s
}

func paramBool(p map[string]any, key string) bool {
	b, _ := p[key].(bool)
	return b
}

func removeStr(list []string, s string) []string {
	var out []string
	for _, l := range list {
		if l != s {
			out = append(out, l)
		}
	}
	return out
}

// Simulate applies the selected fixes to a copy of the inventory behind a
// stored analysis, re-runs the analysis and reports what changed. Real files
// are never touched.
func Simulate(a *model.Analysis, fixIDs []string) (*SimulationResult, error) {
	inv, err := InventoryOf(a)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.Fix{}
	for _, f := range a.Fixes {
		byID[f.ID] = f
	}
	var fixes []*model.Fix
	var skipped []string
	for _, id := range fixIDs {
		f, ok := byID[id]
		if !ok {
			skipped = append(skipped, id+": unknown fix")
			continue
		}
		fixes = append(fixes, f)
	}
	// remove_rule changes list indices, so run those last, highest index first.
	sort.SliceStable(fixes, func(i, j int) bool {
		fi, fj := fixes[i], fixes[j]
		ri, rj := fi.Action == "remove_rule", fj.Action == "remove_rule"
		switch {
		case ri != rj:
			return rj
		case !ri:
			return false
		case fi.Target != fj.Target:
			return fi.Target < fj.Target
		}
		return paramInt(fi.Params, "index") > paramInt(fj.Params, "index")
	})

	res := map[string]*model.Resource{}
	for _, r := range inv.Resources {
		res[r.ID] = r
	}
	var applied []*model.Fix
	for _, f := range fixes {
		if msg := applyFix(inv, res, f); msg != "" {
			skipped = append(skipped, f.ID+": "+msg)
			continue
		}
		applied = append(applied, f)
	}
	// Drop resources removed by fixes.
	var kept []*model.Resource
	for _, r := range inv.Resources {
		if res[r.ID] != nil {
			kept = append(kept, r)
		}
	}
	inv.Resources = kept

	// Recompute with the limits of the original analysis so both sides compare like for like.
	lim := a.PathSearch.Limits
	if lim.Validate() != nil {
		lim = model.DefaultSearchLimits() // snapshots from before limits were recorded
	}
	after := FromInventoryWith(a.Name+" (what-if)", inv, lim)
	after.Inputs = a.Inputs
	after.Sources = a.Sources

	if applied == nil {
		applied = []*model.Fix{}
	}
	out := &SimulationResult{
		Applied: applied, Skipped: skipped,
		PathsResolved: []*model.Path{}, PathsRemaining: []*model.Path{}, PathsNew: []*model.Path{}, FindingsResolved: []*model.Finding{},
		PathsBefore: len(a.Paths), PathsAfter: len(after.Paths),
		FindingsBefore: len(a.Findings), FindingsAfter: len(after.Findings),
		After: after,
	}
	afterSig := map[string]*model.Path{}
	for _, p := range after.Paths {
		afterSig[p.Signature] = p
	}
	beforeSig := map[string]bool{}
	for _, p := range a.Paths {
		beforeSig[p.Signature] = true
		if _, still := afterSig[p.Signature]; still {
			out.PathsRemaining = append(out.PathsRemaining, p)
		} else {
			out.PathsResolved = append(out.PathsResolved, p)
		}
	}
	for _, p := range after.Paths {
		if !beforeSig[p.Signature] {
			out.PathsNew = append(out.PathsNew, p)
		}
	}
	afterF := map[string]bool{}
	for _, f := range after.Findings {
		afterF[f.ID] = true
	}
	for _, f := range a.Findings {
		if !afterF[f.ID] {
			out.FindingsResolved = append(out.FindingsResolved, f)
		}
	}
	return out, nil
}

func container(r *model.Resource, name string) *model.Container {
	if r.Workload == nil {
		return nil
	}
	for i := range r.Workload.Containers {
		if r.Workload.Containers[i].Name == name {
			return &r.Workload.Containers[i]
		}
	}
	return nil
}

// applyFix mutates the cloned inventory; it returns a message if the fix cannot be applied.
func applyFix(inv *parse.Inventory, res map[string]*model.Resource, f *model.Fix) string {
	r := res[f.Target]
	p := f.Params
	switch f.Action {
	case "add_default_deny":
		ns := paramStr(p, "namespace")
		id := fmt.Sprintf("k8s:NetworkPolicy/%s/cloudgraph-default-deny", ns)
		np := &model.Resource{ID: id, Domain: model.DomainKubernetes, Kind: model.KindNetworkPolicy, Type: "NetworkPolicy",
			Name: "cloudgraph-default-deny", Namespace: ns, Src: model.Source{File: "(what-if)"}, NetPol: &model.NetPolSpec{Ingress: true}}
		inv.Resources = append(inv.Resources, np)
		res[id] = np
		return ""
	}
	if r == nil {
		return "target " + f.Target + " no longer exists"
	}
	switch f.Action {
	case "remove_resource":
		delete(res, r.ID)
	case "set_container_field":
		ct := container(r, paramStr(p, "container"))
		if ct == nil {
			return "container not found"
		}
		v := paramBool(p, "value")
		switch paramStr(p, "field") {
		case "privileged":
			ct.Privileged = &v
		case "allowPrivilegeEscalation":
			ct.AllowPrivEsc = &v
		case "runAsNonRoot":
			ct.RunAsNonRoot = &v
			if v && ct.RunAsUser != nil && *ct.RunAsUser == 0 {
				uid := int64(10001)
				ct.RunAsUser = &uid
			}
		case "readOnlyRootFilesystem":
			ct.ReadOnlyRootFS = &v
		default:
			return "unsupported field"
		}
	case "drop_caps":
		ct := container(r, paramStr(p, "container"))
		if ct == nil {
			return "container not found"
		}
		var keep []string
		for _, c := range ct.CapAdd {
			if len(model.DangerousCaps([]string{c})) == 0 {
				keep = append(keep, c)
			}
		}
		ct.CapAdd = keep
	case "remove_volume":
		w := r.Workload
		name, src := paramStr(p, "name"), paramStr(p, "source")
		var vols []model.Volume
		for _, v := range w.Volumes {
			if (name != "" && v.Name == name) || (src != "" && v.Source == src) {
				for i := range w.Containers {
					w.Containers[i].Mounts = removeStr(w.Containers[i].Mounts, v.Name)
				}
				continue
			}
			vols = append(vols, v)
		}
		w.Volumes = vols
	case "unset_host_ns":
		switch paramStr(p, "field") {
		case "hostNetwork":
			r.Workload.HostNetwork = false
			r.Workload.NetworkMode = ""
		case "hostPID":
			r.Workload.HostPID = false
		case "hostIPC":
			r.Workload.HostIPC = false
		}
	case "bind_localhost":
		idx := paramInt(p, "index")
		if idx < 0 || idx >= len(r.Workload.Ports) {
			return "port not found"
		}
		r.Workload.Ports[idx].BindAddr = "127.0.0.1"
	case "externalize_env":
		ct := container(r, paramStr(p, "container"))
		if ct == nil {
			return "container not found"
		}
		for i := range ct.Env {
			if ct.Env[i].Name == paramStr(p, "env") {
				ct.Env[i].LooksSecret, ct.Env[i].Literal = false, false
			}
		}
	case "set_automount":
		f := false
		r.Workload.AutomountToken = &f
	case "remove_rule":
		i := paramInt(p, "index")
		if i < 0 || i >= len(r.Rules) {
			return "rule index out of range"
		}
		r.Rules = append(r.Rules[:i:i], r.Rules[i+1:]...)
	case "tf_restrict_cidr":
		for i := range r.TF.Ingress {
			for j, c := range r.TF.Ingress[i].CIDRs {
				if c == "0.0.0.0/0" || c == "::/0" {
					r.TF.Ingress[i].CIDRs[j] = "10.0.0.0/8"
				}
			}
		}
	case "tf_private_bucket":
		t := true
		r.TF.ACL, r.TF.PublicAccessBlock = "private", &t
	case "tf_remove_admin":
		var keep []model.TFStatement
		for _, st := range r.TF.Statements {
			if st.Effect == "Allow" && (model.HasExact(st.Actions, "*") || strings.Contains(strings.Join(st.Actions, ","), "iam:")) {
				continue
			}
			keep = append(keep, st)
		}
		r.TF.Statements = keep
		var arns []string
		for _, a := range r.TF.ManagedARNs {
			if !strings.HasSuffix(a, "/AdministratorAccess") {
				arns = append(arns, a)
			}
		}
		r.TF.ManagedARNs = arns
	case "tf_private_db":
		fv := false
		r.TF.PubliclyAccessible = &fv
	case "tf_require_imdsv2":
		r.TF.HTTPTokens = "required"
	default:
		return "unsupported action " + f.Action
	}
	return ""
}
