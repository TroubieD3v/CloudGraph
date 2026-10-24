package parse

import (
	"strings"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/mask"
	"github.com/TroubieD3v/cloudgraph/internal/model"
)

func parseOne(t *testing.T, name, content string) *Inventory {
	t.Helper()
	inv, err := Parse([]File{{Name: name, Data: []byte(content)}})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func find(inv *Inventory, id string) *model.Resource {
	for _, r := range inv.Resources {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func TestDetect(t *testing.T) {
	cases := []struct{ name, content, want string }{
		{"a.yml", "services:\n  web:\n    image: x\n", FormatCompose},
		{"a.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n", FormatKubernetes},
		{"plan.json", `{"format_version":"1.2","planned_values":{}}`, FormatTerraform},
		{"other.json", `{"hello":"world"}`, FormatUnknown},
		{"values.yaml", "replicaCount: 2\n", FormatUnknown},
	}
	for _, c := range cases {
		if got := Detect(File{Name: c.name, Data: []byte(c.content)}); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestComposePortsEnvAndLines(t *testing.T) {
	inv := parseOne(t, "docker-compose.yml", `services:
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
      - "6000:6000/udp"
      - 9000
    environment:
      POSTGRES_PASSWORD: hunter2
      URL: postgres://user:pw123@db:5432/x
      MODE: prod
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/data:ro
      - named:/n
`)
	db := find(inv, "compose:service/db")
	if db == nil {
		t.Fatal("service not parsed")
	}
	if db.Src.Line != 2 {
		t.Errorf("service line = %d, want 2", db.Src.Line)
	}
	ports := db.Workload.Ports
	if len(ports) != 3 || ports[0].BindAddr != "127.0.0.1" || ports[0].Host != 5432 || ports[1].Container != 6000 || ports[2].Container != 9000 {
		t.Errorf("ports parsed wrongly: %+v", ports)
	}
	for _, e := range db.Workload.Containers[0].Env {
		switch e.Name {
		case "POSTGRES_PASSWORD":
			if e.Value != mask.Redacted || !e.LooksSecret {
				t.Errorf("password not masked: %+v", e)
			}
		case "URL":
			if strings.Contains(e.Value, "pw123") || !strings.Contains(e.Value, "@db:5432") {
				t.Errorf("url credentials must be masked but host kept: %q", e.Value)
			}
		case "MODE":
			if e.Value != "prod" || e.LooksSecret {
				t.Errorf("plain var changed: %+v", e)
			}
		}
	}
	kinds := map[string]string{}
	for _, v := range db.Workload.Volumes {
		kinds[v.Source] = v.Kind
	}
	if kinds["/var/run/docker.sock"] != "socket" || kinds["./data"] != "bind" || kinds["named"] != "volume" {
		t.Errorf("volume kinds wrong: %v", kinds)
	}
	if !db.Sensitive {
		t.Error("postgres service should be a sensitive data store")
	}
}

func TestKubernetesWorkloadParsing(t *testing.T) {
	inv := parseOne(t, "k.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  template:
    metadata:
      labels:
        app: web
    spec:
      serviceAccountName: web-sa
      hostNetwork: true
      securityContext:
        runAsNonRoot: true
      containers:
        - name: c
          image: nginx
          securityContext:
            privileged: true
          env:
            - name: API_TOKEN
              value: abc
            - name: FROM_SECRET
              valueFrom:
                secretKeyRef:
                  name: s
                  key: k
---
apiVersion: v1
kind: Secret
metadata:
  name: s
stringData:
  password: topsecretvalue
`)
	w := find(inv, "k8s:Deployment/shop/web")
	if w == nil {
		t.Fatalf("deployment missing: %+v", inv.Resources)
	}
	ct := w.Workload.Containers[0]
	if ct.Privileged == nil || !*ct.Privileged || ct.Locs["privileged"] != 20 {
		t.Errorf("privileged/line wrong: %+v loc=%d", ct.Privileged, ct.Locs["privileged"])
	}
	if ct.RunAsNonRoot == nil || !*ct.RunAsNonRoot {
		t.Error("pod-level runAsNonRoot should be inherited")
	}
	if w.Workload.ServiceAccount != "web-sa" || !w.Workload.HostNetwork || w.Workload.PodLabels["app"] != "web" {
		t.Errorf("pod spec wrong: %+v", w.Workload)
	}
	if ct.Env[0].Value != mask.Redacted || ct.Env[1].SecretRef != "s" {
		t.Errorf("env wrong: %+v", ct.Env)
	}
	sec := find(inv, "k8s:Secret/default/s")
	if sec == nil {
		t.Fatal("secret missing")
	}
	keys, _ := sec.Attrs["keys"].([]string)
	if len(keys) != 1 || keys[0] != "password" {
		t.Errorf("only key names should be kept, got %v", sec.Attrs)
	}
}

func TestKubernetesHelmTemplateIsRejectedWithMessage(t *testing.T) {
	inv := parseOne(t, "t.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Values.name }}\n")
	if len(inv.Warnings) == 0 {
		t.Error("expected a warning for templated manifest")
	}
}

func TestTerraformMaskingAndRefs(t *testing.T) {
	plan := `{
 "format_version": "1.2",
 "planned_values": {"root_module": {"resources": [
  {"address":"aws_db_instance.d","mode":"managed","type":"aws_db_instance","name":"d",
   "values":{"password":"supersecret","publicly_accessible":true,"port":5432},"sensitive_values":{"password":true}},
  {"address":"aws_security_group.s","mode":"managed","type":"aws_security_group","name":"s",
   "values":{"ingress":[{"from_port":22,"to_port":22,"protocol":"tcp","cidr_blocks":["0.0.0.0/0"]}]},"sensitive_values":{}}
 ]}},
 "configuration": {"root_module": {"resources": [
  {"address":"aws_db_instance.d","expressions":{"vpc_security_group_ids":{"references":["aws_security_group.s.id","aws_security_group.s"]}}}
 ]}}
}`
	inv := parseOne(t, "plan.json", plan)
	d := find(inv, "tf:aws_db_instance.d")
	if d == nil {
		t.Fatal("db missing")
	}
	vals := d.Attrs["values"].(map[string]any)
	if vals["password"] != mask.Redacted {
		t.Errorf("password not masked: %v", vals["password"])
	}
	if refs := d.Refs["vpc_security_group_ids"]; len(refs) != 1 || refs[0] != "tf:aws_security_group.s" {
		t.Errorf("refs = %v", d.Refs)
	}
	sg := find(inv, "tf:aws_security_group.s")
	if len(sg.TF.Ingress) != 1 || sg.TF.Ingress[0].From != 22 || sg.Src.Line == 0 {
		t.Errorf("sg parse wrong: %+v line=%d", sg.TF, sg.Src.Line)
	}
}

func TestTerraformStandaloneRulesAndModules(t *testing.T) {
	plan := `{
 "format_version": "1.2",
 "planned_values": {"root_module": {"resources": [
  {"address":"aws_security_group.web","mode":"managed","type":"aws_security_group","name":"web","values":{"ingress":[]}},
  {"address":"aws_vpc_security_group_ingress_rule.ssh","mode":"managed","type":"aws_vpc_security_group_ingress_rule","name":"ssh",
   "values":{"cidr_ipv4":"0.0.0.0/0","from_port":22,"to_port":22,"ip_protocol":"tcp"}},
  {"address":"aws_vpc_security_group_ingress_rule.orphan","mode":"managed","type":"aws_vpc_security_group_ingress_rule","name":"orphan",
   "values":{"cidr_ipv4":"0.0.0.0/0","ip_protocol":"-1"}}
 ], "child_modules": [{"address":"module.app","resources":[
  {"address":"module.app.aws_instance.this","mode":"managed","type":"aws_instance","name":"this","values":{"associate_public_ip_address":true}},
  {"address":"module.app.aws_security_group.this","mode":"managed","type":"aws_security_group","name":"this","values":{"ingress":[]}}
 ]}]}},
 "configuration": {"root_module": {
  "resources": [{"address":"aws_vpc_security_group_ingress_rule.ssh","expressions":{"security_group_id":{"references":["aws_security_group.web.id","aws_security_group.web"]}}}],
  "module_calls": {"app": {"module": {"resources": [
    {"address":"aws_instance.this","expressions":{"vpc_security_group_ids":{"references":["aws_security_group.this.id","aws_security_group.this"]}}}
  ]}}}
 }}
}`
	inv := parseOne(t, "plan.json", plan)
	web := find(inv, "tf:aws_security_group.web")
	if web == nil || len(web.TF.Ingress) != 1 || web.TF.Ingress[0].From != 22 || web.TF.Ingress[0].CIDRs[0] != "0.0.0.0/0" {
		t.Fatalf("vpc ingress rule not merged into its group: %+v", web)
	}
	if find(inv, "tf:aws_vpc_security_group_ingress_rule.ssh") != nil {
		t.Error("merged rule should not remain as a separate resource")
	}
	orphan := find(inv, "tf:aws_vpc_security_group_ingress_rule.orphan")
	if orphan == nil || orphan.TF.Ingress[0].To != 65535 {
		t.Errorf("rule without a group in the plan must be kept: %+v", orphan)
	}
	inst := find(inv, "tf:module.app.aws_instance.this")
	if inst == nil || len(inst.Refs["vpc_security_group_ids"]) != 1 || inst.Refs["vpc_security_group_ids"][0] != "tf:module.app.aws_security_group.this" {
		t.Errorf("module references not resolved: %+v", inst)
	}
}
