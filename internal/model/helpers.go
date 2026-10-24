package model

import (
	"strings"
)

var escapeCaps = map[string]bool{
	"SYS_ADMIN": true, "SYS_MODULE": true, "ALL": true, "DAC_READ_SEARCH": true,
	"SYS_RAWIO": true, "BPF": true, "SYS_PTRACE": true, "NET_ADMIN": true,
}

// DangerousCaps returns the capabilities from caps that weaken container isolation.
func DangerousCaps(caps []string) []string {
	var out []string
	for _, c := range caps {
		c = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
		if escapeCaps[c] {
			out = append(out, c)
		}
	}
	return out
}

// EscapeCaps returns the subset of capabilities that realistically enable a
// container escape on their own (or with host namespaces).
func EscapeCaps(caps []string) []string {
	var out []string
	for _, c := range DangerousCaps(caps) {
		switch c {
		case "SYS_ADMIN", "SYS_MODULE", "ALL", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF":
			out = append(out, c)
		}
	}
	return out
}

var riskyHostPrefixes = []string{
	"/etc", "/proc", "/sys", "/root", "/var/run", "/run", "/var/lib/docker", "/var/lib/kubelet",
	"/var/lib/containerd", "/boot", "/dev", "/home", "/usr", "/bin", "/sbin", "/lib",
}

// RiskyHostPath reports whether mounting p from the host exposes sensitive data
// or the container runtime.
func RiskyHostPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "/" || strings.Contains(p, "docker.sock") || strings.Contains(p, "containerd.sock") || strings.Contains(p, "crio.sock") {
		return true
	}
	for _, pre := range riskyHostPrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// EffectiveAutomount returns whether a pod gets a service account token.
func EffectiveAutomount(w *Workload, saAutomount *bool) bool {
	if w != nil && w.AutomountToken != nil {
		return *w.AutomountToken
	}
	if saAutomount != nil {
		return *saAutomount
	}
	return true
}

// Has reports whether list contains one of the wanted values or "*".
func Has(list []string, wanted ...string) bool {
	for _, l := range list {
		if l == "*" {
			return true
		}
		for _, w := range wanted {
			if l == w {
				return true
			}
		}
	}
	return false
}

// HasExact is like Has but does not treat "*" as a match.
func HasExact(list []string, wanted ...string) bool {
	for _, l := range list {
		for _, w := range wanted {
			if l == w {
				return true
			}
		}
	}
	return false
}

// Scope renders "cluster" or the namespace for capability IDs.
func Scope(ns string) string {
	if ns == "" {
		return "cluster"
	}
	return ns
}

// Bool dereferences a *bool with a default.
func Bool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
