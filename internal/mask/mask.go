// Package mask removes sensitive values before they are stored, logged or
// exported. Parsers call it at the earliest possible moment so that raw secrets
// never reach the inventory, the SQLite store, SARIF or HTML reports.
package mask

import (
	"regexp"
	"strings"
)

// Redacted is the placeholder that replaces secret values.
const Redacted = "***MASKED***"

var secretKey = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key|auth|bearer|cert(ificate)?[_-]?key|connection[_-]?string|user_data)`)

var urlCreds = regexp.MustCompile(`(://[^:/@\s]+:)[^@\s]+@`)

// IsSecretKey reports whether a variable / attribute name suggests a secret.
func IsSecretKey(name string) bool { return secretKey.MatchString(name) }

// IsReference reports whether v is a variable reference rather than a literal.
func IsReference(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "{{")
}

// EnvValue masks v when name looks like a secret and v is a literal.
// It returns the (possibly masked) value and whether it was a hard-coded secret.
func EnvValue(name, v string) (string, bool) {
	// Credentials embedded in URLs (postgres://user:pass@host/db): keep the host, drop the password.
	if urlCreds.MatchString(v) {
		return urlCreds.ReplaceAllString(v, "${1}"+Redacted+"@"), true
	}
	// FOO_PASSWORD_FILE points at a secret file, it is not the secret itself.
	if strings.HasSuffix(strings.ToUpper(name), "_FILE") {
		return v, false
	}
	if IsSecretKey(name) && !IsReference(v) {
		return Redacted, true
	}
	return v, false
}

// Any walks arbitrary decoded JSON and masks values stored under secret-looking keys.
func Any(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			switch tv := val.(type) {
			case map[string]any, []any, nil:
				out[k] = Any(val)
			case string:
				if IsSecretKey(k) && tv != "" {
					out[k] = Redacted
				} else {
					out[k] = tv
				}
			default:
				out[k] = val
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Any(val)
		}
		return out
	}
	return v
}

// ByPath masks values addressed by a Terraform "sensitive_values" tree: a
// structure that mirrors the value and contains true where a value is sensitive.
func ByPath(value any, marks any) any {
	switch m := marks.(type) {
	case bool:
		if m {
			return Redacted
		}
		return value
	case map[string]any:
		vm, ok := value.(map[string]any)
		if !ok {
			return value
		}
		out := make(map[string]any, len(vm))
		for k, v := range vm {
			if sub, has := m[k]; has {
				out[k] = ByPath(v, sub)
			} else {
				out[k] = v
			}
		}
		return out
	case []any:
		vs, ok := value.([]any)
		if !ok {
			return value
		}
		out := make([]any, len(vs))
		for i, v := range vs {
			if i < len(m) {
				out[i] = ByPath(v, m[i])
			} else {
				out[i] = v
			}
		}
		return out
	}
	return value
}
