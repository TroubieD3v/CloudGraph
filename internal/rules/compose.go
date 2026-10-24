package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/graph"
	"github.com/TroubieD3v/cloudgraph/internal/model"
)

var adminPorts = map[int]string{
	22: "SSH", 2375: "Docker API", 2376: "Docker API (TLS)", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
	27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB", 1433: "MSSQL", 3389: "RDP", 9042: "Cassandra",
}

func init() {
	wl := []string{model.KindWorkload}

	register(Rule{
		ID: "CG-DC-001", Title: "Privileged container", Severity: model.SevCritical, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Remove `privileged: true`. Grant only the specific capabilities the service needs with cap_add.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if model.Bool(ct.Privileged, false) {
					line := ct.Locs["privileged"]
					e, ok := c.setBoolLine(r.Src.File, line, false)
					out = append(out, Draft{Key: ct.Name, Line: line, Path: "privileged",
						Message: fmt.Sprintf("Service %s runs privileged: it has all host capabilities and access to host devices.", r.Name),
						Fix: newFix("set_container_field", r.ID, "Set privileged: false on "+r.Name,
							map[string]any{"container": ct.Name, "field": "privileged", "value": false}, okEdits(e, ok)...)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-002", Title: "Container runtime socket mounted", Severity: model.SevCritical, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Do not mount docker.sock into application containers. Use a socket proxy with a read-only API allow-list if access is unavoidable.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, v := range r.Workload.Volumes {
				if v.Kind == "socket" {
					e, ok := c.deleteLines(r.Src.File, v.Span[0], v.Span[1])
					out = append(out, Draft{Key: v.Source, Line: v.Line, Path: "volumes",
						Message: fmt.Sprintf("Service %s mounts %s. Anyone controlling this container controls the Docker daemon and therefore the host.", r.Name, v.Source),
						Fix: newFix("remove_volume", r.ID, "Remove the "+v.Source+" mount from "+r.Name,
							map[string]any{"source": v.Source}, okEdits(e, ok)...)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-003", Title: "Sensitive host path mounted", Severity: model.SevHigh, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Mount named volumes or narrow, read-only subdirectories instead of system paths such as /, /etc or /proc.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, v := range r.Workload.Volumes {
				if v.Kind == "bind" && model.RiskyHostPath(v.Source) {
					e, ok := c.deleteLines(r.Src.File, v.Span[0], v.Span[1])
					out = append(out, Draft{Key: v.Source, Line: v.Line, Path: "volumes",
						Message: fmt.Sprintf("Service %s bind-mounts host path %s.", r.Name, v.Source),
						Fix: newFix("remove_volume", r.ID, "Remove the "+v.Source+" host mount from "+r.Name,
							map[string]any{"source": v.Source}, okEdits(e, ok)...)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-004", Title: "Host network namespace", Severity: model.SevMedium, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Remove `network_mode: host` and publish only the ports that are needed.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if !r.Workload.HostNetwork {
				return nil
			}
			line := r.Workload.Locs["network_mode"]
			e, ok := c.deleteLines(r.Src.File, line, line)
			return []Draft{{Line: line, Path: "network_mode",
				Message: fmt.Sprintf("Service %s shares the host network stack, bypassing Docker network isolation.", r.Name),
				Fix:     newFix("unset_host_ns", r.ID, "Remove host networking from "+r.Name, map[string]any{"field": "hostNetwork"}, okEdits(e, ok)...)}}
		},
	})

	register(Rule{
		ID: "CG-DC-005", Title: "Host PID / IPC namespace", Severity: model.SevHigh, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Remove `pid: host` and `ipc: host`.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, f := range []struct {
				on        bool
				key, name string
			}{{r.Workload.HostPID, "pid", "hostPID"}, {r.Workload.HostIPC, "ipc", "hostIPC"}} {
				if f.on {
					line := r.Workload.Locs[f.key]
					e, ok := c.deleteLines(r.Src.File, line, line)
					out = append(out, Draft{Key: f.key, Line: line, Path: f.key,
						Message: fmt.Sprintf("Service %s uses the host %s namespace.", r.Name, strings.ToUpper(f.key)),
						Fix:     newFix("unset_host_ns", r.ID, "Remove "+f.key+": host from "+r.Name, map[string]any{"field": f.name}, okEdits(e, ok)...)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-006", Title: "Dangerous Linux capabilities added", Severity: model.SevHigh, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Drop ALL capabilities and add back only what is required; never add SYS_ADMIN, SYS_PTRACE or ALL.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if d := model.DangerousCaps(ct.CapAdd); len(d) > 0 {
					out = append(out, Draft{Key: ct.Name, Line: ct.Locs["cap_add"], Path: "cap_add",
						Message: fmt.Sprintf("Service %s adds capabilities %s.", r.Name, strings.Join(d, ", ")),
						Fix:     newFix("drop_caps", r.ID, "Remove dangerous capabilities from "+r.Name, map[string]any{"container": ct.Name})})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-007", Title: "Sensitive port published on all interfaces", Severity: model.SevHigh, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Bind the port to 127.0.0.1 (\"127.0.0.1:5432:5432\") or drop `ports:` and use the internal Docker network.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for i, p := range r.Workload.Ports {
				if !graph.PortIsAllInterfaces(p.BindAddr) {
					continue
				}
				name, risky := adminPorts[p.Container]
				if !risky && !r.Workload.DataStore {
					continue
				}
				if name == "" {
					name = "data store"
				}
				e, ok := c.bindLocalhost(r.Src.File, p.Line)
				out = append(out, Draft{Key: fmt.Sprint(p.Container), Line: p.Line, Path: "ports",
					Message: fmt.Sprintf("Service %s publishes %s port %d on every host interface.", r.Name, name, p.Container),
					Fix: newFix("bind_localhost", r.ID, fmt.Sprintf("Bind port %d of %s to 127.0.0.1", p.Container, r.Name),
						map[string]any{"port": p.Container, "index": i}, okEdits(e, ok)...)})
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-008", Title: "Hard-coded secret in environment", Severity: model.SevHigh, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Use Compose `secrets:` or reference a variable (`${DB_PASSWORD}`) supplied at deploy time; never commit literal credentials.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				for _, ev := range ct.Env {
					if ev.LooksSecret {
						e, ok := c.externalizeEnv(r.Src.File, ev)
						out = append(out, Draft{Key: ev.Name, Line: ev.Line, Path: "environment." + ev.Name,
							Message: fmt.Sprintf("Service %s sets %s to a literal value (masked in this report).", r.Name, ev.Name),
							Fix: newFix("externalize_env", r.ID, fmt.Sprintf("Read %s from the environment instead of the file", ev.Name),
								map[string]any{"container": ct.Name, "env": ev.Name}, okEdits(e, ok)...)})
					}
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-009", Title: "Unpinned image tag", Severity: model.SevLow, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Pin images to an explicit version or digest so deployments are reproducible and reviewable.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if strings.HasPrefix(ct.Image, "build:") || ct.Image == "" {
					continue
				}
				if unpinned(ct.Image) {
					out = append(out, Draft{Key: ct.Name, Line: ct.Locs["image"], Path: "image",
						Message: fmt.Sprintf("Image %q has no version tag or uses :latest.", ct.Image)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-010", Title: "Container runs as root", Severity: model.SevLow, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Set `user: \"10001:10001\"` (or build the image with a non-root USER).",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for _, ct := range r.Workload.Containers {
				if strings.HasPrefix(ct.Image, "build:") {
					continue // the Dockerfile may already drop privileges; cannot be determined here
				}
				if ct.RunAsNonRoot == nil || !*ct.RunAsNonRoot {
					out = append(out, Draft{Key: ct.Name, Line: ct.Locs["_"],
						Message: fmt.Sprintf("Service %s does not set a non-root user; the image default (often root) applies.", r.Name)})
				}
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-DC-011", Title: "Seccomp / AppArmor confinement disabled", Severity: model.SevHigh, Domain: model.DomainCompose, Kinds: wl,
		Remediation: "Remove `seccomp:unconfined` / `apparmor:unconfined` from security_opt.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if v, ok := r.Attrs["unconfinedProfile"].(string); ok {
				return []Draft{{Line: r.Locs["security_opt"], Path: "security_opt",
					Message: fmt.Sprintf("Service %s sets security_opt %q, disabling default syscall filtering.", r.Name, v)}}
			}
			return nil
		},
	})
}

func unpinned(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	base := image[strings.LastIndex(image, "/")+1:]
	i := strings.Index(base, ":")
	return i < 0 || base[i+1:] == "latest"
}

var portLine = regexp.MustCompile(`^(\s*-\s*)("?)(\d)`)

// bindLocalhost rewrites a short-syntax port mapping to bind 127.0.0.1.
func (c *Ctx) bindLocalhost(file string, n int) (model.Edit, bool) {
	l, ok := c.line(file, n)
	if !ok {
		return model.Edit{}, false
	}
	m := portLine.FindStringSubmatch(l)
	if m == nil {
		return model.Edit{}, false
	}
	return c.replaceLine(file, n, portLine.ReplaceAllString(l, "${1}${2}127.0.0.1:${3}"))
}

// externalizeEnv replaces a literal env value with a ${NAME} reference.
func (c *Ctx) externalizeEnv(file string, ev model.EnvVar) (model.Edit, bool) {
	l, ok := c.line(file, ev.Line)
	if !ok {
		return model.Edit{}, false
	}
	m := kvLine.FindStringSubmatch(l)
	if m == nil || m[2] != ev.Name {
		return model.Edit{}, false
	}
	return c.replaceLine(file, ev.Line, m[1]+m[2]+m[3]+"${"+ev.Name+"}")
}
