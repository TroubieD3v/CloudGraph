package mask

import (
	"regexp"
	"strings"
)

var (
	yamlKV    = regexp.MustCompile(`^(\s*(?:-\s+)?)([A-Za-z0-9_.\-/]+|"[^"]+")(\s*[:=]\s*)(.*)$`)
	jsonKV    = regexp.MustCompile(`^(\s*"([^"]+)"\s*:\s*)("(?:[^"\\]|\\.)*")(,?\s*)$`)
	yamlName  = regexp.MustCompile(`^\s*-?\s*name:\s*["']?([^"'\s]+)["']?\s*$`)
	yamlValue = regexp.MustCompile(`^(\s*value:\s*)(.+)$`)
	topKey    = regexp.MustCompile(`^(\s*)([A-Za-z0-9_.\-]+):\s*$`)
)

// Lines returns a copy of a source file with secret values replaced, so the
// source viewer and patches can show real context without leaking credentials.
// It understands YAML/env style `KEY: value` and `KEY=value`, JSON members,
// credentials embedded in URLs, Kubernetes env `name:`/`value:` pairs, and
// every value inside the data/stringData of a Secret manifest.
func Lines(lines []string) []string {
	out := make([]string, len(lines))
	copy(out, lines)

	inSecretDoc := false
	secretDataIndent := -1
	prevSecretName := false
	for i, l := range lines {
		trim := strings.TrimSpace(l)
		if trim == "---" {
			inSecretDoc, secretDataIndent, prevSecretName = false, -1, false
			continue
		}
		if strings.HasPrefix(trim, "kind:") && strings.Contains(trim, "Secret") && !strings.Contains(trim, "SecretStore") {
			inSecretDoc = true
		}

		// Leaving a data/stringData block when indentation returns to its level.
		if secretDataIndent >= 0 && trim != "" && indent(l) <= secretDataIndent {
			secretDataIndent = -1
		}
		if inSecretDoc && secretDataIndent < 0 {
			if m := topKey.FindStringSubmatch(l); m != nil && (m[2] == "data" || m[2] == "stringData") {
				secretDataIndent = len(m[1])
				continue
			}
		}
		if secretDataIndent >= 0 {
			if m := yamlKV.FindStringSubmatch(l); m != nil && m[4] != "" {
				out[i] = m[1] + m[2] + m[3] + Redacted
			}
			continue
		}

		// env: - name: SOME_SECRET / value: literal
		if prevSecretName {
			if m := yamlValue.FindStringSubmatch(l); m != nil && !IsReference(strings.Trim(m[2], `"' `)) {
				out[i] = m[1] + Redacted
				prevSecretName = false
				continue
			}
		}
		prevSecretName = false
		if m := yamlName.FindStringSubmatch(l); m != nil && IsSecretKey(m[1]) {
			prevSecretName = true
		}

		if urlCreds.MatchString(l) {
			out[i] = urlCreds.ReplaceAllString(l, "${1}"+Redacted+"@")
			continue
		}
		if m := jsonKV.FindStringSubmatch(l); m != nil {
			if IsSecretKey(m[2]) && m[3] != `""` && m[3] != "null" {
				out[i] = m[1] + `"` + Redacted + `"` + m[4]
				continue
			}
		}
		if m := yamlKV.FindStringSubmatch(l); m != nil {
			key := strings.Trim(m[2], `"`)
			val := strings.Trim(strings.TrimSpace(m[4]), `"'`)
			if v, hit := EnvValue(key, val); hit && v != val {
				out[i] = m[1] + m[2] + m[3] + Redacted
				continue
			}
		}
		// KEY=value inside a list item, e.g.  - "DB_PASSWORD=hunter2"
		if idx := strings.Index(l, "="); idx > 0 {
			left := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l[:idx]), "-")), `"' `)
			if IsSecretKey(left) && !strings.ContainsAny(left, " :") {
				val := strings.Trim(strings.TrimSpace(l[idx+1:]), `"'`)
				if !IsReference(val) {
					out[i] = l[:idx+1] + Redacted + closingQuote(l)
					continue
				}
			}
		}
	}
	return out
}

func indent(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }

func closingQuote(l string) string {
	t := strings.TrimRight(l, " 	,")
	if strings.HasSuffix(t, `"`) || strings.HasSuffix(t, "'") {
		return t[len(t)-1:]
	}
	return ""
}
