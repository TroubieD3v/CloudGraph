package parse

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/mask"
	"github.com/TroubieD3v/cloudgraph/internal/model"
)

type tfPlan struct {
	PlannedValues struct {
		RootModule tfModule `json:"root_module"`
	} `json:"planned_values"`
	ResourceChanges []struct {
		Address string `json:"address"`
		Change  struct {
			AfterUnknown map[string]any `json:"after_unknown"`
		} `json:"change"`
	} `json:"resource_changes"`
	Configuration struct {
		RootModule tfConfigModule `json:"root_module"`
	} `json:"configuration"`
}

type tfModule struct {
	Address      string       `json:"address"`
	Resources    []tfResource `json:"resources"`
	ChildModules []tfModule   `json:"child_modules"`
}

type tfResource struct {
	Address         string         `json:"address"`
	Mode            string         `json:"mode"`
	Type            string         `json:"type"`
	Name            string         `json:"name"`
	Values          map[string]any `json:"values"`
	SensitiveValues map[string]any `json:"sensitive_values"`
}

type tfConfigModule struct {
	Resources []struct {
		Address     string                  `json:"address"`
		Expressions map[string]tfExpression `json:"expressions"`
	} `json:"resources"`
	ModuleCalls map[string]struct {
		Module tfConfigModule `json:"module"`
	} `json:"module_calls"`
}

type tfExpression struct {
	References []string `json:"references"`
}

func (m *tfExpression) UnmarshalJSON(b []byte) error {
	// expressions can be objects, arrays of blocks, or constants; only the
	// object form carries references.
	var v struct {
		References []string `json:"references"`
	}
	if json.Unmarshal(b, &v) == nil {
		m.References = v.References
	}
	return nil
}

func flattenResources(m tfModule, out *[]tfResource) {
	*out = append(*out, m.Resources...)
	for _, c := range m.ChildModules {
		flattenResources(c, out)
	}
}

func flattenConfig(m tfConfigModule, prefix string, out map[string]map[string][]string) {
	for _, r := range m.Resources {
		refs := map[string][]string{}
		for attr, ex := range r.Expressions {
			if len(ex.References) > 0 {
				refs[attr] = ex.References
			}
		}
		out[prefix+r.Address] = refs
	}
	for name, mc := range m.ModuleCalls {
		flattenConfig(mc.Module, prefix+"module."+name+".", out)
	}
}

// refAddress reduces "aws_security_group.web.id" to "aws_security_group.web".
func refAddress(ref, prefix string) string {
	ref = strings.TrimPrefix(ref, prefix)
	parts := strings.Split(ref, ".")
	if len(parts) < 2 {
		return ""
	}
	if parts[0] == "data" || parts[0] == "var" || parts[0] == "local" || parts[0] == "each" || parts[0] == "count" {
		return ""
	}
	return prefix + parts[0] + "." + parts[1]
}

func tfID(addr string) string { return "tf:" + addr }

func parseTerraform(f File) ([]*model.Resource, []string, error) {
	var plan tfPlan
	if err := json.Unmarshal(f.Data, &plan); err != nil {
		return nil, nil, fmt.Errorf("invalid Terraform plan JSON: %w", err)
	}
	var raws []tfResource
	flattenResources(plan.PlannedValues.RootModule, &raws)
	cfg := map[string]map[string][]string{}
	flattenConfig(plan.Configuration.RootModule, "", cfg)

	unknown := map[string][]string{}
	for _, rc := range plan.ResourceChanges {
		for k, v := range rc.Change.AfterUnknown {
			if b, ok := v.(bool); ok && b {
				unknown[rc.Address] = append(unknown[rc.Address], k)
			}
		}
	}

	lines := strings.Split(string(f.Data), "\n")
	lineOf := func(addr string) int {
		needle := `"address": "` + addr + `"`
		needle2 := `"address":"` + addr + `"`
		for i, l := range lines {
			if strings.Contains(l, needle) || strings.Contains(l, needle2) {
				return i + 1
			}
		}
		return 0
	}

	known := map[string]tfResource{}
	for _, r := range raws {
		if r.Mode == "managed" || r.Mode == "" {
			known[r.Address] = r
		}
	}

	byAddr := map[string]*model.Resource{}
	var out []*model.Resource
	var warns []string
	skipped := map[string]int{}

	resolveRefs := func(addr string) map[string][]string {
		prefix := ""
		if strings.HasPrefix(addr, "module.") {
			parts := strings.Split(addr, ".")
			// module.<name>. repeated until the resource type
			for i := 0; i+1 < len(parts) && parts[i] == "module"; i += 2 {
				prefix += parts[i] + "." + parts[i+1] + "."
			}
		}
		res := map[string][]string{}
		for attr, refs := range cfg[addr] {
			seen := map[string]bool{}
			for _, ref := range refs {
				a := refAddress(ref, prefix)
				if a == "" || seen[a] {
					continue
				}
				if _, ok := known[a]; ok {
					seen[a] = true
					res[attr] = append(res[attr], tfID(a))
				}
			}
		}
		return res
	}

	for _, raw := range raws {
		if raw.Mode == "data" {
			continue
		}
		vals := raw.Values
		if vals == nil {
			vals = map[string]any{}
		}
		r := &model.Resource{
			ID: tfID(raw.Address), Domain: model.DomainTerraform, Type: raw.Type, Name: raw.Address,
			Src:  model.Source{File: f.Name, Line: lineOf(raw.Address), Path: raw.Address},
			Refs: resolveRefs(raw.Address),
			TF:   &model.TFSpec{UnknownAttrs: unknown[raw.Address]},
		}
		r.Labels = stringMapOf(vals["tags"])
		switch raw.Type {
		case "aws_security_group":
			r.Kind = model.KindFirewall
			for _, ig := range anyList(vals["ingress"]) {
				r.TF.Ingress = append(r.TF.Ingress, ingressOf(ig))
			}
		case "aws_security_group_rule":
			r.Kind = model.KindFirewall
			if str, _ := vals["type"].(string); str == "ingress" {
				r.TF.Ingress = append(r.TF.Ingress, ingressOf(vals))
			}
		case "aws_instance":
			r.Kind = model.KindInstance
			r.TF.PublicIP = boolOf(vals["associate_public_ip_address"])
			if mo := anyList(vals["metadata_options"]); len(mo) > 0 {
				if m, ok := mo[0].(map[string]any); ok {
					r.TF.HTTPTokens, _ = m["http_tokens"].(string)
				}
			}
			r.TF.Encrypted = rootVolumeEncrypted(vals)
		case "aws_iam_instance_profile":
			r.Kind = model.KindIdentity
		case "aws_iam_role":
			r.Kind = model.KindIdentity
			for _, ip := range anyList(vals["inline_policy"]) {
				if m, ok := ip.(map[string]any); ok {
					r.TF.Statements = append(r.TF.Statements, statementsOf(m["policy"])...)
				}
			}
			r.TF.ManagedARNs = append(r.TF.ManagedARNs, strSliceOf(vals["managed_policy_arns"])...)
		case "aws_iam_policy":
			r.Kind = model.KindPolicy
			r.TF.Statements = statementsOf(vals["policy"])
		case "aws_iam_role_policy", "aws_iam_role_policy_attachment":
			// folded into the role below
			continue
		case "aws_s3_bucket":
			r.Kind = model.KindBucket
			if acl, _ := vals["acl"].(string); acl != "" {
				r.TF.ACL = acl
			}
			if b, _ := vals["bucket"].(string); b != "" {
				r.Attrs = map[string]any{"bucket": b}
			}
			for k, v := range r.Labels {
				lk, lv := strings.ToLower(k), strings.ToLower(v)
				if (lk == "sensitivity" || lk == "dataclassification" || lk == "data-classification" || lk == "data_classification") &&
					(lv == "confidential" || lv == "restricted" || lv == "sensitive" || lv == "pii") {
					r.Sensitive, r.SensitiveReason = true, "Bucket tagged "+k+"="+v
				}
			}
		case "aws_s3_bucket_public_access_block", "aws_s3_bucket_acl", "aws_s3_bucket_server_side_encryption_configuration":
			// folded into the bucket below
			continue
		case "aws_db_instance":
			r.Kind = model.KindDatabase
			r.TF.PubliclyAccessible = boolOf(vals["publicly_accessible"])
			r.TF.Encrypted = boolOf(vals["storage_encrypted"])
			if p, ok := vals["port"].(float64); ok {
				r.TF.Port = int(p)
			}
			r.Sensitive, r.SensitiveReason = true, "Database"
		default:
			skipped[raw.Type]++
			continue
		}
		// Mask before the attributes are stored anywhere.
		masked := mask.ByPath(vals, raw.SensitiveValues)
		masked = mask.Any(masked)
		if r.Attrs == nil {
			r.Attrs = map[string]any{}
		}
		if mm, ok := masked.(map[string]any); ok {
			r.Attrs["values"] = pruneBig(mm)
		}
		byAddr[raw.Address] = r
		out = append(out, r)
	}

	// Fold companion resources into their owners.
	for _, raw := range raws {
		refs := resolveRefs(raw.Address)
		vals := raw.Values
		switch raw.Type {
		case "aws_iam_role_policy":
			if role := first(refs["role"]); role != "" {
				if rr := byID(byAddr, role); rr != nil {
					rr.TF.Statements = append(rr.TF.Statements, statementsOf(vals["policy"])...)
				}
			}
		case "aws_iam_role_policy_attachment":
			role := first(refs["role"])
			rr := byID(byAddr, role)
			if rr == nil {
				continue
			}
			if pol := first(refs["policy_arn"]); pol != "" {
				rr.Refs["policies"] = append(rr.Refs["policies"], pol)
			} else if arn, _ := vals["policy_arn"].(string); arn != "" {
				rr.TF.ManagedARNs = append(rr.TF.ManagedARNs, arn)
			} else {
				rr.TF.UnknownAttrs = append(rr.TF.UnknownAttrs, "policy_arn (attachment "+raw.Address+")")
			}
		case "aws_s3_bucket_public_access_block":
			if b := byID(byAddr, first(refs["bucket"])); b != nil {
				all := true
				for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
					if v := boolOf(vals[k]); v == nil || !*v {
						all = false
					}
				}
				b.TF.PublicAccessBlock = &all
			}
		case "aws_s3_bucket_acl":
			if b := byID(byAddr, first(refs["bucket"])); b != nil {
				if acl, _ := vals["acl"].(string); acl != "" {
					b.TF.ACL = acl
				}
			}
		case "aws_s3_bucket_server_side_encryption_configuration":
			if b := byID(byAddr, first(refs["bucket"])); b != nil {
				t := true
				b.TF.Encrypted = &t
			}
		case "aws_security_group_rule":
			// merge rule into its group
			if sg := byID(byAddr, first(refs["security_group_id"])); sg != nil && sg.Type == "aws_security_group" {
				if t, _ := vals["type"].(string); t == "ingress" {
					sg.TF.Ingress = append(sg.TF.Ingress, ingressOf(vals))
				}
			}
		}
	}
	// aws_security_group_rule resources have been merged; drop standalone copies.
	filtered := out[:0]
	for _, r := range out {
		if r.Type == "aws_security_group_rule" {
			continue
		}
		filtered = append(filtered, r)
	}
	out = filtered

	for _, r := range out {
		if r.Refs == nil {
			r.Refs = map[string][]string{}
		}
		if len(r.TF.UnknownAttrs) > 0 {
			sort.Strings(r.TF.UnknownAttrs)
		}
	}
	if len(skipped) > 0 {
		var ts []string
		for t, n := range skipped {
			ts = append(ts, fmt.Sprintf("%s×%d", t, n))
		}
		sort.Strings(ts)
		warns = append(warns, fmt.Sprintf("%s: resource types not modelled yet: %s", f.Name, strings.Join(ts, ", ")))
	}
	return out, warns, nil
}

func byID(m map[string]*model.Resource, id string) *model.Resource {
	if id == "" {
		return nil
	}
	return m[strings.TrimPrefix(id, "tf:")]
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}

func boolOf(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

func strSliceOf(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		out = append(out, t)
	}
	return out
}

func stringMapOf(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

func numOf(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func ingressOf(v any) model.TFIngress {
	m, _ := v.(map[string]any)
	ig := model.TFIngress{From: numOf(m["from_port"]), To: numOf(m["to_port"])}
	ig.Protocol, _ = m["protocol"].(string)
	ig.CIDRs = append(strSliceOf(m["cidr_blocks"]), strSliceOf(m["ipv6_cidr_blocks"])...)
	if s, ok := m["cidr_blocks"].(string); ok && s != "" {
		ig.CIDRs = append(ig.CIDRs, s)
	}
	return ig
}

func rootVolumeEncrypted(vals map[string]any) *bool {
	for _, b := range anyList(vals["root_block_device"]) {
		if m, ok := b.(map[string]any); ok {
			return boolOf(m["encrypted"])
		}
	}
	return nil
}

// statementsOf parses an IAM policy document supplied as a JSON string.
func statementsOf(v any) []model.TFStatement {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(s), &doc) != nil || doc.Statement == nil {
		return nil
	}
	type stmt struct {
		Effect   string          `json:"Effect"`
		Action   json.RawMessage `json:"Action"`
		Resource json.RawMessage `json:"Resource"`
	}
	var list []stmt
	if json.Unmarshal(doc.Statement, &list) != nil {
		var one stmt
		if json.Unmarshal(doc.Statement, &one) != nil {
			return nil
		}
		list = []stmt{one}
	}
	strs := func(raw json.RawMessage) []string {
		if raw == nil {
			return nil
		}
		var many []string
		if json.Unmarshal(raw, &many) == nil {
			return many
		}
		var one string
		if json.Unmarshal(raw, &one) == nil {
			return []string{one}
		}
		return nil
	}
	var out []model.TFStatement
	for _, st := range list {
		out = append(out, model.TFStatement{Effect: st.Effect, Actions: strs(st.Action), Resources: strs(st.Resource)})
	}
	return out
}

// pruneBig drops very large attribute values (such as user_data blobs) so
// snapshots stay small; they are already masked.
func pruneBig(m map[string]any) map[string]any {
	for k, v := range m {
		if s, ok := v.(string); ok && len(s) > 2000 {
			m[k] = s[:200] + "…(truncated)"
		}
	}
	return m
}
