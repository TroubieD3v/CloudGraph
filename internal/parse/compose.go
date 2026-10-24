package parse

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/TroubieD3v/cloudgraph/internal/mask"
	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// ComposeServiceID returns the resource ID of a compose service.
func ComposeServiceID(name string) string { return "compose:service/" + name }

func parseCompose(f File) ([]*model.Resource, []string, error) {
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(f.Data)).Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("invalid YAML: %w", err)
	}
	root := resolve(&doc)
	var out []*model.Resource
	var warns []string

	declaredNets := map[string]bool{}
	usedNets := map[string]int{} // network -> first line
	for _, p := range pairs(get(root, "networks")) {
		declaredNets[p.Key] = true
		out = append(out, &model.Resource{
			ID: "compose:network/" + p.Key, Domain: model.DomainCompose, Kind: model.KindNetwork, Type: "compose.network",
			Name: p.Key, Src: model.Source{File: f.Name, Line: p.Line, EndLine: lastLine(p.Val)},
		})
	}
	for _, p := range pairs(get(root, "secrets")) {
		out = append(out, &model.Resource{
			ID: "compose:secret/" + p.Key, Domain: model.DomainCompose, Kind: model.KindSecret, Type: "compose.secret",
			Name: p.Key, Src: model.Source{File: f.Name, Line: p.Line, EndLine: lastLine(p.Val)},
			Sensitive: true, SensitiveReason: "Compose secret",
		})
	}

	for _, sp := range pairs(get(root, "services")) {
		r := composeService(f, sp, &warns)
		for _, n := range r.Workload.Networks {
			if _, ok := usedNets[n]; !ok {
				usedNets[n] = r.Src.Line
			}
		}
		out = append(out, r)
	}
	// The implicit default network (and networks used without declaration).
	for n, line := range usedNets {
		if !declaredNets[n] {
			out = append(out, &model.Resource{
				ID: "compose:network/" + n, Domain: model.DomainCompose, Kind: model.KindNetwork, Type: "compose.network",
				Name: n, Src: model.Source{File: f.Name, Line: line}, Attrs: map[string]any{"implicit": true},
			})
		}
	}
	return out, warns, nil
}

func composeService(f File, sp pair, warns *[]string) *model.Resource {
	n := sp.Val
	r := &model.Resource{
		ID: ComposeServiceID(sp.Key), Domain: model.DomainCompose, Kind: model.KindWorkload, Type: "compose.service",
		Name: sp.Key, Src: model.Source{File: f.Name, Line: sp.Line, EndLine: lastLine(n)},
		Locs:  map[string]int{},
		Attrs: map[string]any{},
	}
	w := &model.Workload{Locs: map[string]int{}}
	ct := model.Container{Name: sp.Key, Image: strAt(n, "image"), Locs: map[string]int{"_": sp.Line}}
	if ct.Image == "" {
		if b := get(n, "build"); b != nil {
			ctx := str(b)
			if ctx == "" {
				ctx = strAt(b, "context")
			}
			ct.Image = "build:" + ctx
			r.Attrs["build"] = true
		}
	}
	ct.Locs["image"] = keyLine(n, "image")

	ct.Privileged = boolPtr(get(n, "privileged"))
	ct.Locs["privileged"] = keyLine(n, "privileged")
	ct.ReadOnlyRootFS = boolPtr(get(n, "read_only"))
	for _, it := range items(get(n, "cap_add")) {
		if v := str(it); v != "" {
			ct.CapAdd = append(ct.CapAdd, v)
			ct.CapAddLines = append(ct.CapAddLines, it.Line)
		}
	}
	ct.Locs["capAddKey"] = keyLine(n, "cap_add")
	ct.CapDrop = strList(get(n, "cap_drop"))
	ct.Locs["cap_add"] = keyLine(n, "cap_add")
	if u := str(get(n, "user")); u != "" {
		uid := strings.SplitN(u, ":", 2)[0]
		if v, err := strconv.ParseInt(uid, 10, 64); err == nil {
			ct.RunAsUser = &v
		}
		nonRoot := uid != "root" && uid != "0"
		ct.RunAsNonRoot = &nonRoot
		ct.Locs["runAsUser"] = keyLine(n, "user")
	}
	for _, so := range strList(get(n, "security_opt")) {
		switch {
		case strings.HasPrefix(so, "no-new-privileges") && (strings.HasSuffix(so, "true") || so == "no-new-privileges"):
			f := false
			ct.AllowPrivEsc = &f
		case strings.Contains(so, "unconfined"):
			r.Attrs["unconfinedProfile"] = so
			r.Locs["security_opt"] = keyLine(n, "security_opt")
		}
	}
	if dig(n, "deploy", "resources", "limits") != nil || get(n, "mem_limit") != nil || get(n, "cpus") != nil {
		ct.HasLimits = true
	}

	// environment: map or list
	envNode := get(n, "environment")
	if envNode != nil && envNode.Kind == yaml.MappingNode {
		for _, p := range pairs(envNode) {
			ev := model.EnvVar{Name: p.Key, Line: p.Line, Literal: true}
			ev.Value, ev.LooksSecret = mask.EnvValue(p.Key, str(p.Val))
			ct.Env = append(ct.Env, ev)
		}
	} else {
		for _, it := range items(envNode) {
			kv := str(it)
			name, val, hasVal := strings.Cut(kv, "=")
			ev := model.EnvVar{Name: name, Line: it.Line}
			if hasVal {
				ev.Literal = true
				ev.Value, ev.LooksSecret = mask.EnvValue(name, val)
			}
			ct.Env = append(ct.Env, ev)
		}
	}
	if ef := get(n, "env_file"); ef != nil {
		files := strList(ef)
		if len(files) == 0 {
			files = []string{str(ef)}
		}
		r.Attrs["envFile"] = files
	}

	// secrets mounted into the service
	for _, s := range items(get(n, "secrets")) {
		name := str(s)
		if name == "" {
			name = strAt(s, "source")
		}
		if name != "" {
			ct.EnvFromSecrets = append(ct.EnvFromSecrets, name)
		}
	}

	// networking
	if nm := str(get(n, "network_mode")); nm != "" {
		w.NetworkMode = nm
		w.Locs["network_mode"] = keyLine(n, "network_mode")
		if nm == "host" {
			w.HostNetwork = true
		}
	}
	if str(get(n, "pid")) == "host" {
		w.HostPID = true
		w.Locs["pid"] = keyLine(n, "pid")
	}
	if str(get(n, "ipc")) == "host" {
		w.HostIPC = true
		w.Locs["ipc"] = keyLine(n, "ipc")
	}
	if nets := get(n, "networks"); nets != nil {
		if nets.Kind == yaml.MappingNode {
			for _, p := range pairs(nets) {
				w.Networks = append(w.Networks, p.Key)
			}
		} else {
			w.Networks = strList(nets)
		}
	} else if w.NetworkMode == "" {
		w.Networks = []string{"default"}
	}
	switch dep := get(n, "depends_on"); {
	case dep == nil:
	case dep.Kind == yaml.MappingNode:
		for _, p := range pairs(dep) {
			w.DependsOn = append(w.DependsOn, p.Key)
		}
	default:
		w.DependsOn = strList(dep)
	}
	for _, l := range strList(get(n, "links")) {
		w.DependsOn = append(w.DependsOn, strings.SplitN(l, ":", 2)[0])
	}

	// ports
	for _, p := range items(get(n, "ports")) {
		if pb, ok := parsePort(p); ok {
			w.Ports = append(w.Ports, pb)
		} else {
			*warns = append(*warns, fmt.Sprintf("%s:%d: cannot parse port mapping of service %s", f.Name, p.Line, sp.Key))
		}
	}

	// volumes / mounts
	for i, v := range items(get(n, "volumes")) {
		vol := model.Volume{Line: v.Line, Span: [2]int{v.Line, lastLine(v)}}
		if v.Kind == yaml.ScalarNode {
			parts := strings.Split(v.Value, ":")
			vol.Source = parts[0]
			if len(parts) > 2 && strings.Contains(parts[len(parts)-1], "ro") {
				vol.ReadOnly = true
			}
		} else {
			vol.Source = strAt(v, "source")
			if b := boolPtr(get(v, "read_only")); b != nil {
				vol.ReadOnly = *b
			}
		}
		switch {
		case strings.Contains(vol.Source, "docker.sock") || strings.Contains(vol.Source, "containerd.sock"):
			vol.Kind = "socket"
		case strings.HasPrefix(vol.Source, "/") || strings.HasPrefix(vol.Source, "./") || strings.HasPrefix(vol.Source, "../") || strings.HasPrefix(vol.Source, "~"):
			vol.Kind = "bind"
		default:
			vol.Kind = "volume"
		}
		vol.Name = fmt.Sprintf("%s-vol%d", sp.Key, i)
		ct.Mounts = append(ct.Mounts, vol.Name)
		w.Volumes = append(w.Volumes, vol)
	}

	if IsDataStoreImage(ct.Image) {
		w.DataStore = true
		r.Sensitive, r.SensitiveReason = true, "Data store service"
	}
	w.Containers = []model.Container{ct}
	r.Workload = w
	return r
}

func parsePort(p *yaml.Node) (model.PortBinding, bool) {
	pb := model.PortBinding{Line: p.Line, Proto: "tcp"}
	if p.Kind == yaml.MappingNode {
		t := intPtr(get(p, "target"))
		if t == nil {
			return pb, false
		}
		pb.Container = int(*t)
		if h := intPtr(get(p, "published")); h != nil {
			pb.Host = int(*h)
		} else if hs := strAt(p, "published"); hs != "" {
			if v, err := strconv.Atoi(strings.SplitN(hs, "-", 2)[0]); err == nil {
				pb.Host = v
			}
		}
		pb.BindAddr = strAt(p, "host_ip")
		if pr := strAt(p, "protocol"); pr != "" {
			pb.Proto = pr
		}
		return pb, true
	}
	s := p.Value
	if i := strings.Index(s, "/"); i >= 0 {
		pb.Proto = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ":")
	atoi := func(v string) (int, bool) {
		v = strings.SplitN(v, "-", 2)[0]
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	var ok bool
	switch len(parts) {
	case 1:
		pb.Container, ok = atoi(parts[0])
	case 2:
		pb.Host, _ = atoi(parts[0])
		pb.Container, ok = atoi(parts[1])
	case 3:
		pb.BindAddr = parts[0]
		pb.Host, _ = atoi(parts[1])
		pb.Container, ok = atoi(parts[2])
	}
	return pb, ok
}
