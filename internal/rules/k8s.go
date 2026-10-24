package rules

import (
	"fmt"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

func containerLine(ct model.Container, key string) int {
	if l := ct.Locs[key]; l > 0 {
		return l
	}
	if l := ct.Locs["securityContext"]; l > 0 {
		return l
	}
	return ct.Locs["_"]
}

// boolFieldFix builds a fix that sets a securityContext boolean, rewriting the
// existing line when present and inserting a new one when securityContext exists.
func (c *Ctx) boolFieldFix(r *model.Resource, ct model.Container, field string, value bool, desc string) *model.Fix {
	params := map[string]any{"container": ct.Name, "field": field, "value": value}
	file := r.Src.File
	if l := ct.Locs[field]; l > 0 {
		if e, ok := c.setBoolLine(file, l, value); ok {
			return newFix("set_container_field", r.ID, desc, params, e)
		}
	}
	if sc := ct.Locs["securityContext"]; sc > 0 {
		if line, ok := c.line(file, sc); ok && !strings.Contains(line, "{") {
			// insert as the first child of securityContext
			if next, ok2 := c.line(file, sc+1); ok2 {
				text := indentOf(next) + fmt.Sprintf("%s: %t", field, value)
				if e, ok3 := c.insertBefore(file, sc+1, text); ok3 {
					return newFix("set_container_field", r.ID, desc, params, e)
				}
			}
		}
	}
	return newFix("set_container_field", r.ID, desc, params)
}

func init() {
	wl := []string{model.KindWorkload}

	register(Rule{
		ID: "CG-K8S-001", Title: "Privileged container", Severity: model.SevCritical, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Set `securityContext.privileged: false` and grant only the specific capabilities required.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if model.Bool(ct.Privileged, false) {
					out = append(out, Draft{Key: ct.Name, Line: containerLine(ct, "privileged"), Path: "securityContext.privileged",
						Message: fmt.Sprintf("Container %q in %s %s is privileged and effectively root on the node.", ct.Name, r.Type, r.Name),
						Fix:     c.boolFieldFix(r, ct, "privileged", false, fmt.Sprintf("Set privileged: false on %s/%s", r.Name, ct.Name))})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-002", Title: "Privilege escalation not disabled", Severity: model.SevMedium, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Set `securityContext.allowPrivilegeEscalation: false`.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if ct.AllowPrivEsc == nil || *ct.AllowPrivEsc {
					out = append(out, Draft{Key: ct.Name, Line: containerLine(ct, "allowPrivilegeEscalation"), Path: "securityContext.allowPrivilegeEscalation",
						Message: fmt.Sprintf("Container %q in %s may gain more privileges than its parent process (allowPrivilegeEscalation is not false).", ct.Name, r.Name),
						Fix:     c.boolFieldFix(r, ct, "allowPrivilegeEscalation", false, fmt.Sprintf("Set allowPrivilegeEscalation: false on %s/%s", r.Name, ct.Name))})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-003", Title: "Container may run as root", Severity: model.SevMedium, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Set `securityContext.runAsNonRoot: true` and a non-zero `runAsUser`.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				rootUser := ct.RunAsUser != nil && *ct.RunAsUser == 0
				if rootUser || ct.RunAsNonRoot == nil || !*ct.RunAsNonRoot {
					msg := fmt.Sprintf("Container %q in %s does not enforce runAsNonRoot.", ct.Name, r.Name)
					if rootUser {
						msg = fmt.Sprintf("Container %q in %s runs as UID 0.", ct.Name, r.Name)
					}
					out = append(out, Draft{Key: ct.Name, Line: containerLine(ct, "runAsNonRoot"), Path: "securityContext.runAsNonRoot", Message: msg,
						Fix: c.boolFieldFix(r, ct, "runAsNonRoot", true, fmt.Sprintf("Set runAsNonRoot: true on %s/%s", r.Name, ct.Name))})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-004", Title: "Sensitive hostPath volume", Severity: model.SevHigh, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Avoid hostPath volumes; use emptyDir, PVCs or CSI drivers. Never mount the container runtime socket.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, v := range r.Workload.Volumes {
				if (v.Kind == "hostPath" && model.RiskyHostPath(v.Source)) || v.Kind == "socket" {
					sev := model.SevHigh
					if v.Kind == "socket" {
						sev = model.SevCritical
					}
					out = append(out, Draft{Key: v.Name, Line: v.Line, Path: "volumes", Severity: sev,
						Message: fmt.Sprintf("%s %s mounts host path %s.", r.Type, r.Name, v.Source),
						Fix: newFix("remove_volume", r.ID, fmt.Sprintf("Remove hostPath volume %s from %s", v.Name, r.Name), map[string]any{"name": v.Name},
							c.removeVolumeEdits(r, v)...)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-005", Title: "Host namespaces shared with pod", Severity: model.SevHigh, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Remove hostNetwork, hostPID and hostIPC unless the workload is a node-level agent.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, f := range []struct {
				on   bool
				name string
			}{{r.Workload.HostNetwork, "hostNetwork"}, {r.Workload.HostPID, "hostPID"}, {r.Workload.HostIPC, "hostIPC"}} {
				if !f.on {
					continue
				}
				line := r.Workload.Locs[f.name]
				fix := newFix("unset_host_ns", r.ID, fmt.Sprintf("Set %s: false on %s", f.name, r.Name), map[string]any{"field": f.name})
				if e, ok := c.setBoolLine(r.Src.File, line, false); ok {
					fix.Edits = edits(e)
				}
				out = append(out, Draft{Key: f.name, Line: line, Path: "spec." + f.name,
					Message: fmt.Sprintf("%s %s sets %s: true.", r.Type, r.Name, f.name), Fix: fix})
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-006", Title: "Dangerous capabilities added", Severity: model.SevHigh, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Drop ALL capabilities and add back only what the process needs.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if d := model.DangerousCaps(ct.CapAdd); len(d) > 0 {
					out = append(out, Draft{Key: ct.Name, Line: containerLine(ct, "capabilities"), Path: "securityContext.capabilities.add",
						Message: fmt.Sprintf("Container %q in %s adds %s.", ct.Name, r.Name, strings.Join(d, ", ")),
						Fix: newFix("drop_caps", r.ID, fmt.Sprintf("Remove dangerous capabilities from %s/%s", r.Name, ct.Name), map[string]any{"container": ct.Name},
							c.dropCapEdits(r.Src.File, ct.Locs["capAddKey"], ct.CapAdd, ct.CapAddLines)...)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-007", Title: "Unpinned image tag", Severity: model.SevLow, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Pin images to a specific version or digest.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if ct.Image != "" && unpinned(ct.Image) {
					out = append(out, Draft{Key: ct.Name, Line: ct.Locs["image"], Path: "image",
						Message: fmt.Sprintf("Image %q has no version tag or uses :latest.", ct.Image)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-008", Title: "No resource limits", Severity: model.SevLow, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Set `resources.limits` for CPU and memory to contain noisy-neighbour and DoS impact.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if !ct.HasLimits {
					out = append(out, Draft{Key: ct.Name, Line: ct.Locs["_"], Path: "resources.limits",
						Message: fmt.Sprintf("Container %q in %s has no resource limits.", ct.Name, r.Name)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-009", Title: "ServiceAccount token mounted into a pod with API permissions", Severity: model.SevMedium, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Set `automountServiceAccountToken: false` on pods that do not call the Kubernetes API.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			sid := fmt.Sprintf("k8s:ServiceAccount/%s/%s", r.Namespace, r.Workload.ServiceAccount)
			sa := c.G.Resource(sid)
			if sa == nil || !model.EffectiveAutomount(r.Workload, sa.AutomountSA) || len(c.G.Out(sid)) == 0 {
				return nil
			}
			line := r.Workload.Locs["automountServiceAccountToken"]
			fix := newFix("set_automount", r.ID, "Set automountServiceAccountToken: false on "+r.Name, map[string]any{"value": false})
			if line > 0 {
				if e, ok := c.setBoolLine(r.Src.File, line, false); ok {
					fix.Edits = edits(e)
				}
			} else if ps := r.Workload.Locs["_podspec"]; ps > 0 {
				if l, ok := c.line(r.Src.File, ps); ok {
					if e, ok2 := c.insertBefore(r.Src.File, ps, indentOf(l)+"automountServiceAccountToken: false"); ok2 {
						fix.Edits = edits(e)
					}
				}
			}
			if line == 0 {
				line = r.Workload.Locs["_podspec"]
			}
			return []Draft{{Line: line, Path: "spec.automountServiceAccountToken",
				Message: fmt.Sprintf("%s %s mounts the token of ServiceAccount %q, which has RBAC bindings.", r.Type, r.Name, r.Workload.ServiceAccount),
				Fix:     fix}}
		},
	})

	rbacRule := func(id, title, sev, remediation string, match func(model.PolicyRule) (string, bool)) {
		register(Rule{
			ID: id, Title: title, Severity: sev, Domain: model.DomainKubernetes, Kinds: []string{model.KindRole}, Remediation: remediation,
			Check: func(c *Ctx, r *model.Resource) []Draft {
				var out []Draft
				for i, rule := range r.Rules {
					if msg, ok := match(rule); ok {
						fix := newFix("remove_rule", r.ID, fmt.Sprintf("Remove overly broad rule #%d from %s %s", i+1, r.Type, r.Name), map[string]any{"index": i})
						end := r.Src.EndLine
						if i+1 < len(r.Rules) {
							end = r.Rules[i+1].Line - 1
						}
						if e, ok := c.deleteLines(r.Src.File, rule.Line, end); ok {
							fix.Edits = edits(e)
						}
						out = append(out, Draft{Key: fmt.Sprint(i), Line: rule.Line, Path: fmt.Sprintf("rules[%d]", i),
							Message: fmt.Sprintf("%s %s: %s (%s).", r.Type, r.Name, msg, describeRuleText(rule)), Fix: fix})
					}
				}
				return out
			},
		})
	}
	rbacRule("CG-K8S-010", "Wildcard RBAC permissions", model.SevCritical,
		"Replace `*` with the explicit resources and verbs required.",
		func(r model.PolicyRule) (string, bool) {
			if model.HasExact(r.Resources, "*") && model.HasExact(r.Verbs, "*") {
				return "grants every verb on every resource", true
			}
			if model.HasExact(r.Verbs, "*") {
				return "grants every verb", true
			}
			if model.HasExact(r.Resources, "*") && len(r.Resources) > 0 {
				return "applies to every resource type", true
			}
			return "", false
		})
	rbacRule("CG-K8S-012", "Role can read Secrets", model.SevHigh,
		"Restrict `secrets` access to named secrets (resourceNames) or remove it; avoid list/watch which exposes all values.",
		func(r model.PolicyRule) (string, bool) {
			if model.HasExact(r.Resources, "secrets") && model.HasExact(r.Verbs, "get", "list", "watch") && len(r.ResourceNames) == 0 {
				return "can read every Secret in scope", true
			}
			return "", false
		})
	rbacRule("CG-K8S-013", "Role can execute commands or create workloads", model.SevMedium,
		"Remove pods/exec and workload create permissions from application roles; they allow lateral movement.",
		func(r model.PolicyRule) (string, bool) {
			if model.HasExact(r.Resources, "pods/exec", "pods/attach") && model.Has(r.Verbs, "create", "get") {
				return "can exec into pods", true
			}
			if model.HasExact(r.Resources, "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs") && model.HasExact(r.Verbs, "create") {
				return "can create workloads and mount any ServiceAccount or Secret", true
			}
			return "", false
		})
	rbacRule("CG-K8S-019", "Role can escalate privileges", model.SevHigh,
		"Remove escalate, bind and impersonate verbs; they bypass RBAC's privilege-escalation prevention.",
		func(r model.PolicyRule) (string, bool) {
			if model.HasExact(r.Verbs, "escalate", "bind", "impersonate") {
				return "can escalate, bind or impersonate", true
			}
			return "", false
		})

	register(Rule{
		ID: "CG-K8S-011", Title: "Binding to cluster-admin", Severity: model.SevCritical, Domain: model.DomainKubernetes, Kinds: []string{model.KindBinding},
		Remediation: "Bind workloads to purpose-built roles instead of cluster-admin.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if r.Binding.RoleName != "cluster-admin" {
				return nil
			}
			return []Draft{{Line: r.Loc("roleRef"), Path: "roleRef",
				Message: fmt.Sprintf("%s %s grants cluster-admin to %s.", r.Type, r.Name, subjectsText(r.Binding)),
				Fix:     removeResourceFix(c, r, "Remove binding "+r.Name+" (cluster-admin)")}}
		},
	})

	register(Rule{
		ID: "CG-K8S-014", Title: "Binding grants permissions to broad groups", Severity: model.SevHigh, Domain: model.DomainKubernetes, Kinds: []string{model.KindBinding},
		Remediation: "Never bind roles to system:unauthenticated, system:authenticated or all ServiceAccounts.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, s := range r.Binding.Subjects {
				broad := s.Kind == "Group" && (s.Name == "system:unauthenticated" || s.Name == "system:authenticated" || s.Name == "system:serviceaccounts")
				defaultSA := s.Kind == "ServiceAccount" && s.Name == "default"
				if broad || defaultSA {
					sev := model.SevHigh
					if s.Name == "system:unauthenticated" {
						sev = model.SevCritical
					}
					what := "group " + s.Name
					if defaultSA {
						what = "the default ServiceAccount of " + s.Namespace + " (inherited by every pod that does not name one)"
					}
					out = append(out, Draft{Key: s.Name, Line: r.Loc("subjects"), Path: "subjects", Severity: sev,
						Message: fmt.Sprintf("%s %s binds %s %s to %s.", r.Type, r.Name, r.Binding.RoleKind, r.Binding.RoleName, what),
						Fix:     removeResourceFix(c, r, "Remove binding "+r.Name)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-015", Title: "Workload not isolated by a NetworkPolicy", Severity: model.SevLow, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Add a default-deny ingress NetworkPolicy per namespace and allow only required flows. Enforcement requires a CNI that supports NetworkPolicy.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if c.G.Isolated(r) {
				return nil
			}
			sev := model.SevLow
			if r.Sensitive {
				sev = model.SevMedium
			}
			return []Draft{{Path: "metadata.namespace", Severity: sev,
				Message: fmt.Sprintf("No ingress NetworkPolicy in the input selects %s %s/%s. Kubernetes then allows all pod traffic to it; actual reachability also depends on policies outside the input and on CNI enforcement.", r.Type, r.Namespace, r.Name),
				Fix: newFix("add_default_deny", "k8s:Namespace/"+r.Namespace, "Add a default-deny ingress NetworkPolicy to namespace "+r.Namespace,
					map[string]any{"namespace": r.Namespace}, defaultDenyFile(r.Namespace))}}
		},
	})

	register(Rule{
		ID: "CG-K8S-016", Title: "Ingress without TLS", Severity: model.SevMedium, Domain: model.DomainKubernetes, Kinds: []string{model.KindIngress},
		Remediation: "Add a `spec.tls` section with a certificate secret (or let cert-manager issue one).",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if r.Ingress.TLS {
				return nil
			}
			return []Draft{{Line: r.Loc("spec"), Path: "spec.tls", Message: fmt.Sprintf("Ingress %s serves traffic without TLS.", r.Name)}}
		},
	})

	register(Rule{
		ID: "CG-K8S-017", Title: "Service exposed outside the cluster", Severity: model.SevInfo, Domain: model.DomainKubernetes, Kinds: []string{model.KindService},
		Remediation: "Confirm the exposure is intended; prefer ClusterIP behind an authenticated Ingress.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if r.Service.Type == "LoadBalancer" || r.Service.Type == "NodePort" {
				return []Draft{{Line: r.Loc("type"), Path: "spec.type", Message: fmt.Sprintf("Service %s is of type %s.", r.Name, r.Service.Type)}}
			}
			return nil
		},
	})

	register(Rule{
		ID: "CG-K8S-018", Title: "Hard-coded secret in environment", Severity: model.SevHigh, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Reference a Secret with `valueFrom.secretKeyRef` (ideally synced from an external secret manager).",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				for _, ev := range ct.Env {
					if ev.LooksSecret {
						out = append(out, Draft{Key: ct.Name + "/" + ev.Name, Line: ev.Line, Path: "env." + ev.Name,
							Message: fmt.Sprintf("Container %q in %s sets %s to a literal value (masked in this report).", ct.Name, r.Name, ev.Name)})
					}
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-020", Title: "Root filesystem is writable", Severity: model.SevLow, Domain: model.DomainKubernetes, Kinds: wl,
		Remediation: "Set `securityContext.readOnlyRootFilesystem: true` and mount emptyDir volumes where writes are needed.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if ct.ReadOnlyRootFS == nil || !*ct.ReadOnlyRootFS {
					out = append(out, Draft{Key: ct.Name, Line: containerLine(ct, "readOnlyRootFilesystem"), Path: "securityContext.readOnlyRootFilesystem",
						Message: fmt.Sprintf("Container %q in %s has a writable root filesystem.", ct.Name, r.Name),
						Fix:     c.boolFieldFix(r, ct, "readOnlyRootFilesystem", true, fmt.Sprintf("Set readOnlyRootFilesystem: true on %s/%s", r.Name, ct.Name))})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-K8S-021", Title: "Secret manifest committed to configuration", Severity: model.SevMedium, Domain: model.DomainKubernetes, Kinds: []string{model.KindSecret},
		Remediation: "Do not commit Secret manifests. Use sealed-secrets, SOPS or an external secrets operator.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if len(attrStrings(r.Attrs["keys"])) == 0 {
				return nil
			}
			return []Draft{{Line: r.Loc("data"), Path: "data", Message: fmt.Sprintf("Secret %s/%s is defined in plain manifests (values omitted from this report).", r.Namespace, r.Name)}}
		},
	})
}

func removeResourceFix(c *Ctx, r *model.Resource, desc string) *model.Fix {
	fix := newFix("remove_resource", r.ID, desc, nil)
	if e, ok := c.deleteLines(r.Src.File, r.Src.Line, r.Src.EndLine); ok {
		fix.Edits = edits(e)
	}
	return fix
}

func subjectsText(b *model.BindingSpec) string {
	var parts []string
	for _, s := range b.Subjects {
		parts = append(parts, s.Kind+" "+s.Name)
	}
	return strings.Join(parts, ", ")
}

func describeRuleText(r model.PolicyRule) string {
	return fmt.Sprintf("resources=[%s] verbs=[%s]", strings.Join(r.Resources, ","), strings.Join(r.Verbs, ","))
}

// defaultDenyFile proposes a new manifest instead of editing an existing one.
func defaultDenyFile(ns string) model.Edit {
	text := strings.Join([]string{
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  name: cloudgraph-default-deny",
		"  namespace: " + ns,
		"spec:",
		"  podSelector: {}",
		`  policyTypes: ["Ingress"]`,
	}, "\n")
	return model.Edit{File: "cloudgraph-fixes/default-deny-" + ns + ".yaml", StartLine: 1, EndLine: 0, Replace: text, New: true}
}
