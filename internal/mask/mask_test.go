package mask

import (
	"strings"
	"testing"
)

func TestEnvValue(t *testing.T) {
	cases := []struct {
		name, val string
		masked    bool
	}{
		{"DB_PASSWORD", "hunter2", true},
		{"DB_PASSWORD", "${DB_PASSWORD}", false},
		{"DB_PASSWORD_FILE", "/run/secrets/x", false},
		{"API_TOKEN", "abc", true},
		{"LOG_LEVEL", "debug", false},
		{"DATABASE_URL", "postgres://u:pw@db:5432/x", true},
		{"DATABASE_URL", "postgres://db:5432/x", false},
	}
	for _, c := range cases {
		v, hit := EnvValue(c.name, c.val)
		if hit != c.masked {
			t.Errorf("%s=%s: hit=%v", c.name, c.val, hit)
		}
		if hit && strings.Contains(v, "pw") && strings.Contains(c.val, "pw") && strings.Contains(v, ":pw@") {
			t.Errorf("password survived: %s", v)
		}
	}
}

func TestAnyMasksNestedSecretsButKeepsBooleans(t *testing.T) {
	in := map[string]any{
		"password": "x", "manage_master_user_password": true, "nested": map[string]any{"api_key": "k", "name": "n"},
		"list": []any{map[string]any{"token": "t"}},
	}
	out := Any(in).(map[string]any)
	if out["password"] != Redacted || out["manage_master_user_password"] != true {
		t.Errorf("top level: %v", out)
	}
	if out["nested"].(map[string]any)["api_key"] != Redacted || out["nested"].(map[string]any)["name"] != "n" {
		t.Errorf("nested: %v", out["nested"])
	}
	if out["list"].([]any)[0].(map[string]any)["token"] != Redacted {
		t.Errorf("list: %v", out["list"])
	}
}

func TestByPath(t *testing.T) {
	v := map[string]any{"a": "1", "b": []any{"x", "y"}, "c": "keep"}
	marks := map[string]any{"a": true, "b": []any{false, true}}
	out := ByPath(v, marks).(map[string]any)
	if out["a"] != Redacted || out["c"] != "keep" {
		t.Errorf("%v", out)
	}
	if b := out["b"].([]any); b[0] != "x" || b[1] != Redacted {
		t.Errorf("%v", b)
	}
}

func TestLines(t *testing.T) {
	src := strings.Split(`services:
  db:
    environment:
      POSTGRES_PASSWORD: admin123
      URL: postgres://u:topsecretpw@db/x
      MODE: prod
      - "API_TOKEN=abc123"
---
apiVersion: v1
kind: Deployment
spec:
  env:
    - name: SESSION_SECRET
      value: demo-value
    - name: LOG_LEVEL
      value: info
---
apiVersion: v1
kind: Secret
stringData:
  anything: plain-text
  other: more
metadata:
  name: s
{
  "password": "jsonsecret",
  "name": "ok"
}`, "\n")
	got := strings.Join(Lines(src), "\n")
	for _, leaked := range []string{"admin123", "topsecretpw", "abc123", "demo-value", "plain-text", "more", "jsonsecret"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q in:\n%s", leaked, got)
		}
	}
	for _, kept := range []string{"MODE: prod", "value: info", "name: s", `"name": "ok"`, "@db/x"} {
		if !strings.Contains(got, kept) {
			t.Errorf("over-masked, lost %q in:\n%s", kept, got)
		}
	}
	if len(Lines(src)) != len(src) {
		t.Error("line count must be preserved so line numbers stay valid")
	}
}
