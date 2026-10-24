package parse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/TroubieD3v/cloudgraph/internal/mask"
	"github.com/TroubieD3v/cloudgraph/internal/model"
)

var clusterScoped = map[string]bool{
	"Namespace": true, "ClusterRole": true, "ClusterRoleBinding": true, "Node": true,
	"PersistentVolume": true, "StorageClass": true, "CustomResourceDefinition": true,
}

var dataStoreImages = []string{"postgres", "mysql", "mariadb", "mongo", "redis", "memcached", "elasticsearch",
	"opensearch", "cassandra", "mssql", "couchdb", "influxdb", "clickhouse", "etcd"}

// IsDataStoreImage reports whether an image reference looks like a database.
func IsDataStoreImage(image string) bool {
	base := image
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.IndexAny(base, ":@"); i >= 0 {
		base = base[:i]
	}
	base = strings.ToLower(base)
	for _, d := range dataStoreImages {
		if base == d || strings.HasPrefix(base, d+"-") || strings.HasSuffix(base, "-"+d) {
			return true
		}
	}
	return false
}

func k8sID(kind, ns, name string) string {
	if clusterScoped[kind] || ns == "" {
		return fmt.Sprintf("k8s:%s/%s", kind, name)
	}
	return fmt.Sprintf("k8s:%s/%s/%s", kind, ns, name)
}

func parseKubernetes(f File) ([]*model.Resource, []string, error) {
	dec := yaml.NewDecoder(bytes.NewReader(f.Data))
	var out []*model.Resource
	var warns []string
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, warns, fmt.Errorf("invalid YAML (templated manifests such as Helm charts must be rendered first): %w", err)
		}
		root := resolve(&doc)
		if root == nil || root.Kind != yaml.MappingNode {
			continue
		}
		out = append(out, k8sObject(f, root, &warns)...)
	}
	return out, warns, nil
}

func k8sObject(f File, n *yaml.Node, warns *[]string) []*model.Resource {
	kind := strAt(n, "kind")
	if kind == "" {
		return nil
	}
	if kind == "List" {
		var out []*model.Resource
		for _, it := range items(get(n, "items")) {
			out = append(out, k8sObject(f, it, warns)...)
		}
		return out
	}
	name := strAt(n, "metadata", "name")
	ns := strAt(n, "metadata", "namespace")
	if name == "" {
		*warns = append(*warns, fmt.Sprintf("%s:%d: %s without metadata.name, skipped", f.Name, n.Line, kind))
		return nil
	}
	if ns == "" && !clusterScoped[kind] {
		ns = "default"
	}
	r := &model.Resource{
		ID:          k8sID(kind, ns, name),
		Domain:      model.DomainKubernetes,
		Type:        kind,
		Name:        name,
		Namespace:   ns,
		Src:         model.Source{File: f.Name, Line: n.Line, EndLine: lastLine(n)},
		Labels:      strMap(dig(n, "metadata", "labels")),
		Annotations: strMap(dig(n, "metadata", "annotations")),
		Locs:        map[string]int{},
		Attrs:       map[string]any{},
	}
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController":
		r.Kind = model.KindWorkload
		specNode := get(n, "spec")
		podNode := specNode
		podMeta := get(n, "metadata")
		if kind != "Pod" {
			podNode = dig(n, "spec", "template", "spec")
			podMeta = dig(n, "spec", "template", "metadata")
		}
		r.Workload = parsePod(podNode, podMeta, kind == "Pod", r)
	case "CronJob":
		r.Kind = model.KindWorkload
		r.Workload = parsePod(dig(n, "spec", "jobTemplate", "spec", "template", "spec"),
			dig(n, "spec", "jobTemplate", "spec", "template", "metadata"), false, r)
	case "Service":
		r.Kind = model.KindService
		svc := &model.ServiceSpec{Type: strAt(n, "spec", "type"), Selector: strMap(dig(n, "spec", "selector"))}
		if svc.Type == "" {
			svc.Type = "ClusterIP"
		}
		for _, p := range items(dig(n, "spec", "ports")) {
			if v := intPtr(get(p, "port")); v != nil {
				svc.Ports = append(svc.Ports, int(*v))
			}
		}
		r.Service = svc
		r.Locs["type"] = keyLine(get(n, "spec"), "type")
	case "Ingress":
		r.Kind = model.KindIngress
		r.Ingress = parseIngress(n, r)
	case "ServiceAccount":
		r.Kind = model.KindServiceAccount
		r.AutomountSA = boolPtr(get(n, "automountServiceAccountToken"))
		r.Locs["automountServiceAccountToken"] = keyLine(n, "automountServiceAccountToken")
	case "Role", "ClusterRole":
		r.Kind = model.KindRole
		if get(n, "aggregationRule") != nil {
			r.Attrs["aggregated"] = true
		}
		for _, rl := range items(get(n, "rules")) {
			r.Rules = append(r.Rules, model.PolicyRule{
				APIGroups:     strList(get(rl, "apiGroups")),
				Resources:     strList(get(rl, "resources")),
				ResourceNames: strList(get(rl, "resourceNames")),
				Verbs:         strList(get(rl, "verbs")),
				Line:          rl.Line,
			})
		}
		r.Locs["rules"] = keyLine(n, "rules")
	case "RoleBinding", "ClusterRoleBinding":
		r.Kind = model.KindBinding
		b := &model.BindingSpec{
			RoleKind: strAt(n, "roleRef", "kind"),
			RoleName: strAt(n, "roleRef", "name"),
			Cluster:  kind == "ClusterRoleBinding",
		}
		for _, s := range items(get(n, "subjects")) {
			sub := model.Subject{Kind: strAt(s, "kind"), Name: strAt(s, "name"), Namespace: strAt(s, "namespace")}
			if sub.Kind == "ServiceAccount" && sub.Namespace == "" {
				sub.Namespace = ns
			}
			b.Subjects = append(b.Subjects, sub)
		}
		r.Binding = b
		r.Locs["roleRef"] = keyLine(n, "roleRef")
		r.Locs["subjects"] = keyLine(n, "subjects")
	case "NetworkPolicy":
		r.Kind = model.KindNetworkPolicy
		r.NetPol = parseNetPol(n)
	case "Secret":
		r.Kind = model.KindSecret
		r.Sensitive, r.SensitiveReason = true, "Kubernetes Secret"
		var keys []string
		for _, sec := range []string{"data", "stringData"} {
			for _, p := range pairs(get(n, sec)) {
				keys = append(keys, p.Key)
			}
		}
		sort.Strings(keys)
		// Values are intentionally dropped, only key names are kept.
		r.Attrs["keys"] = keys
		r.Attrs["secretType"] = strAt(n, "type")
		r.Locs["data"] = max(keyLine(n, "data"), keyLine(n, "stringData"))
	case "ConfigMap":
		r.Kind = model.KindConfigMap
	case "Namespace":
		r.Kind = model.KindNamespace
	default:
		return nil // CRDs and other kinds are out of scope
	}
	return []*model.Resource{r}
}

func parsePod(spec, meta *yaml.Node, isPod bool, r *model.Resource) *model.Workload {
	w := &model.Workload{
		PodLabels: strMap(get(meta, "labels")),
		Locs:      map[string]int{"_podspec": 0},
	}
	if spec == nil {
		return w
	}
	w.Locs["_podspec"] = spec.Line
	if isPod && w.PodLabels == nil {
		w.PodLabels = r.Labels
	}
	w.ServiceAccount = strAt(spec, "serviceAccountName")
	if w.ServiceAccount == "" {
		w.ServiceAccount = strAt(spec, "serviceAccount")
	}
	if w.ServiceAccount == "" {
		w.ServiceAccount = "default"
	} else {
		w.Locs["serviceAccountName"] = max(keyLine(spec, "serviceAccountName"), keyLine(spec, "serviceAccount"))
	}
	w.AutomountToken = boolPtr(get(spec, "automountServiceAccountToken"))
	w.Locs["automountServiceAccountToken"] = keyLine(spec, "automountServiceAccountToken")
	for _, k := range []struct {
		key string
		dst *bool
	}{{"hostNetwork", &w.HostNetwork}, {"hostPID", &w.HostPID}, {"hostIPC", &w.HostIPC}} {
		if b := boolPtr(get(spec, k.key)); b != nil && *b {
			*k.dst = true
			w.Locs[k.key] = keyLine(spec, k.key)
		}
	}

	podSC := get(spec, "securityContext")
	podNonRoot := boolPtr(get(podSC, "runAsNonRoot"))
	podUser := intPtr(get(podSC, "runAsUser"))

	for _, v := range items(get(spec, "volumes")) {
		vol := model.Volume{Name: strAt(v, "name"), Kind: "other", Line: v.Line}
		switch {
		case get(v, "hostPath") != nil:
			vol.Kind, vol.Source = "hostPath", strAt(v, "hostPath", "path")
			vol.Line = keyLine(v, "hostPath")
			if strings.HasSuffix(vol.Source, "docker.sock") || strings.HasSuffix(vol.Source, "containerd.sock") || strings.HasSuffix(vol.Source, "crio.sock") {
				vol.Kind = "socket"
			}
		case get(v, "secret") != nil:
			vol.Kind, vol.Source = "secret", strAt(v, "secret", "secretName")
		case get(v, "configMap") != nil:
			vol.Kind, vol.Source = "configMap", strAt(v, "configMap", "name")
		case get(v, "emptyDir") != nil:
			vol.Kind = "emptyDir"
		case get(v, "persistentVolumeClaim") != nil:
			vol.Kind, vol.Source = "pvc", strAt(v, "persistentVolumeClaim", "claimName")
		}
		w.Volumes = append(w.Volumes, vol)
	}

	collect := func(list *yaml.Node, init bool) {
		for i, c := range items(list) {
			ct := model.Container{
				Name:  strAt(c, "name"),
				Image: strAt(c, "image"),
				Locs:  map[string]int{"_": c.Line, "image": keyLine(c, "image")},
			}
			if ct.Name == "" {
				ct.Name = fmt.Sprintf("container-%d", i)
			}
			if init {
				ct.Name = "init:" + ct.Name
			}
			sc := get(c, "securityContext")
			ct.Privileged = boolPtr(get(sc, "privileged"))
			ct.AllowPrivEsc = boolPtr(get(sc, "allowPrivilegeEscalation"))
			ct.RunAsNonRoot = boolPtr(get(sc, "runAsNonRoot"))
			ct.RunAsUser = intPtr(get(sc, "runAsUser"))
			ct.ReadOnlyRootFS = boolPtr(get(sc, "readOnlyRootFilesystem"))
			if ct.RunAsNonRoot == nil {
				ct.RunAsNonRoot = podNonRoot
			}
			if ct.RunAsUser == nil {
				ct.RunAsUser = podUser
			}
			ct.CapAdd = strList(dig(sc, "capabilities", "add"))
			ct.CapDrop = strList(dig(sc, "capabilities", "drop"))
			for _, key := range []string{"privileged", "allowPrivilegeEscalation", "runAsNonRoot", "runAsUser", "readOnlyRootFilesystem"} {
				if l := keyLine(sc, key); l > 0 {
					ct.Locs[key] = l
				}
			}
			ct.Locs["securityContext"] = keyLine(c, "securityContext")
			ct.Locs["capabilities"] = keyLine(sc, "capabilities")
			ct.Locs["resources"] = keyLine(c, "resources")
			if dig(c, "resources", "limits") != nil {
				ct.HasLimits = true
			}
			for _, e := range items(get(c, "env")) {
				ev := model.EnvVar{Name: strAt(e, "name"), Line: e.Line}
				if ref := strAt(e, "valueFrom", "secretKeyRef", "name"); ref != "" {
					ev.SecretRef = ref
				} else if get(e, "value") != nil {
					ev.Literal = true
					ev.Value, ev.LooksSecret = mask.EnvValue(ev.Name, strAt(e, "value"))
				}
				ct.Env = append(ct.Env, ev)
			}
			for _, ef := range items(get(c, "envFrom")) {
				if ref := strAt(ef, "secretRef", "name"); ref != "" {
					ct.EnvFromSecrets = append(ct.EnvFromSecrets, ref)
				}
			}
			for _, vm := range items(get(c, "volumeMounts")) {
				ct.Mounts = append(ct.Mounts, strAt(vm, "name"))
			}
			for _, p := range items(get(c, "ports")) {
				if cp := intPtr(get(p, "containerPort")); cp != nil {
					w.Ports = append(w.Ports, model.PortBinding{Container: int(*cp), Proto: strings.ToLower(strAt(p, "protocol")), Line: p.Line})
				}
			}
			if IsDataStoreImage(ct.Image) {
				w.DataStore = true
			}
			w.Containers = append(w.Containers, ct)
		}
	}
	collect(get(spec, "initContainers"), true)
	collect(get(spec, "containers"), false)

	if r.Annotation("cloudgraph.io/sensitive") == "true" || w.DataStore {
		r.Sensitive = true
		r.SensitiveReason = "Data store"
		if w.DataStore {
			r.SensitiveReason = "Data store workload"
		}
	}
	return w
}

func parseIngress(n *yaml.Node, r *model.Resource) *model.IngressSpec {
	ing := &model.IngressSpec{}
	if tls := get(dig(n, "spec"), "tls"); tls != nil && len(items(tls)) > 0 {
		ing.TLS = true
	}
	r.Locs["spec"] = keyLine(n, "spec")
	addBackend := func(b *yaml.Node) {
		if b == nil {
			return
		}
		svc := strAt(b, "service", "name")
		if svc == "" {
			svc = strAt(b, "serviceName") // networking.k8s.io/v1beta1
		}
		if svc != "" {
			ing.Backends = append(ing.Backends, model.BackendRef{Service: svc, Line: b.Line})
		}
	}
	addBackend(dig(n, "spec", "defaultBackend"))
	for _, rule := range items(dig(n, "spec", "rules")) {
		if h := strAt(rule, "host"); h != "" {
			ing.Hosts = append(ing.Hosts, h)
		}
		for _, p := range items(dig(rule, "http", "paths")) {
			addBackend(get(p, "backend"))
		}
	}
	return ing
}

func parseNetPol(n *yaml.Node) *model.NetPolSpec {
	np := &model.NetPolSpec{}
	sel := dig(n, "spec", "podSelector")
	np.PodSelector = strMap(get(sel, "matchLabels"))
	if get(sel, "matchExpressions") != nil {
		np.Unresolvable = true
	}
	types := strList(dig(n, "spec", "policyTypes"))
	ingressRules := get(dig(n, "spec"), "ingress")
	for _, t := range types {
		switch t {
		case "Ingress":
			np.Ingress = true
		case "Egress":
			np.Egress = true
		}
	}
	// policyTypes defaults to Ingress (plus Egress if egress rules exist).
	if len(types) == 0 {
		np.Ingress = true
		if get(dig(n, "spec"), "egress") != nil {
			np.Egress = true
		}
	}
	for _, rule := range items(ingressRules) {
		from := items(get(rule, "from"))
		if len(from) == 0 {
			np.AllowSources = append(np.AllowSources, model.NetPolPeer{AllowAll: true})
			continue
		}
		for _, f := range from {
			peer := model.NetPolPeer{}
			if ps := get(f, "podSelector"); ps != nil {
				peer.HasPodSelector = true
				peer.PodSelector = strMap(get(ps, "matchLabels"))
				if get(ps, "matchExpressions") != nil {
					np.Unresolvable = true
				}
			}
			if ns := get(f, "namespaceSelector"); ns != nil {
				peer.HasNamespaceSel = true
				peer.NamespaceSelector = strMap(get(ns, "matchLabels"))
				if get(ns, "matchExpressions") != nil {
					np.Unresolvable = true
				}
			}
			if ib := get(f, "ipBlock"); ib != nil {
				peer.IPBlock = strAt(ib, "cidr")
			}
			np.AllowSources = append(np.AllowSources, peer)
		}
	}
	return np
}
