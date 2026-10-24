package graph

import (
	"fmt"
	"path"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// PublicCIDR reports whether a CIDR block is open to the whole Internet.
func PublicCIDR(c string) bool { return c == "0.0.0.0/0" || c == "::/0" }

// PublicIngress returns the ingress rules reachable from the Internet.
func PublicIngress(r *model.Resource) []model.TFIngress {
	if r.TF == nil {
		return nil
	}
	var out []model.TFIngress
	for _, ig := range r.TF.Ingress {
		for _, c := range ig.CIDRs {
			if PublicCIDR(c) {
				out = append(out, ig)
				break
			}
		}
	}
	return out
}

// PortRange renders a rule's ports for labels.
func PortRange(ig model.TFIngress) string {
	proto := ig.Protocol
	if proto == "-1" || proto == "" {
		return "all traffic"
	}
	if ig.From == ig.To {
		return fmt.Sprintf("%s/%d", proto, ig.From)
	}
	return fmt.Sprintf("%s/%d-%d", proto, ig.From, ig.To)
}

func covers(ig model.TFIngress, port int) bool {
	if ig.Protocol == "-1" {
		return true
	}
	return ig.From <= port && port <= ig.To
}

// RoleStatements returns the statements effectively attached to a role.
func (g *Graph) RoleStatements(role *model.Resource) ([]model.TFStatement, []string) {
	stmts := append([]model.TFStatement(nil), role.TF.Statements...)
	var sources []string
	for _, pid := range role.Refs["policies"] {
		if p := g.byID[pid]; p != nil && p.TF != nil {
			stmts = append(stmts, p.TF.Statements...)
			sources = append(sources, p.Name)
		}
	}
	for _, arn := range role.TF.ManagedARNs {
		name := arn[strings.LastIndex(arn, "/")+1:]
		sources = append(sources, name)
		switch name {
		case "AdministratorAccess":
			stmts = append(stmts, model.TFStatement{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}})
		case "IAMFullAccess":
			stmts = append(stmts, model.TFStatement{Effect: "Allow", Actions: []string{"iam:*"}, Resources: []string{"*"}})
		case "AmazonS3FullAccess":
			stmts = append(stmts, model.TFStatement{Effect: "Allow", Actions: []string{"s3:*"}, Resources: []string{"*"}})
		case "AmazonS3ReadOnlyAccess":
			stmts = append(stmts, model.TFStatement{Effect: "Allow", Actions: []string{"s3:Get*", "s3:List*"}, Resources: []string{"*"}})
		case "SecretsManagerReadWrite":
			stmts = append(stmts, model.TFStatement{Effect: "Allow", Actions: []string{"secretsmanager:*"}, Resources: []string{"*"}})
		}
	}
	return stmts, sources
}

func actionAllowed(stmts []model.TFStatement, wide bool, actions ...string) bool {
	for _, st := range stmts {
		if st.Effect != "Allow" {
			continue
		}
		if wide && !wideResource(st.Resources) {
			continue
		}
		for _, pat := range st.Actions {
			for _, a := range actions {
				if ok, _ := path.Match(strings.ToLower(pat), strings.ToLower(a)); ok {
					return true
				}
			}
		}
	}
	return false
}

func wideResource(res []string) bool {
	for _, r := range res {
		if r == "*" || r == "arn:aws:s3:::*" || r == "arn:aws:secretsmanager:*:*:secret:*" {
			return true
		}
	}
	return false
}

// IAMCapabilities derives account-level capabilities from policy statements.
func IAMCapabilities(stmts []model.TFStatement) []capDef {
	var out []capDef
	switch {
	case actionAllowed(stmts, true, "*"):
		out = append(out, capDef{"admin", "AWS account administrator", 98, "Action \"*\" on Resource \"*\" allows full control of the account"})
	}
	if len(out) == 0 {
		if actionAllowed(stmts, true, "iam:PassRole", "iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PutRolePolicy",
			"iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy", "iam:AttachUserPolicy") {
			out = append(out, capDef{"iam-escalation", "IAM privilege escalation", 90, "IAM write actions on all resources allow granting administrator rights"})
		}
		if actionAllowed(stmts, true, "secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters") {
			out = append(out, capDef{"secrets-read", "Read AWS secrets", 80, "can read all Secrets Manager / SSM secrets"})
		}
		if actionAllowed(stmts, true, "s3:GetObject") {
			out = append(out, capDef{"s3-data", "Read all S3 data", 72, "can read objects in every bucket"})
		}
	}
	return out
}

func (g *Graph) buildTerraform() {
	var tf []*model.Resource
	for _, r := range g.Resources {
		if r.Domain == model.DomainTerraform {
			tf = append(tf, r)
		}
	}
	if len(tf) == 0 {
		return
	}

	for _, r := range tf {
		switch r.Kind {
		case model.KindFirewall:
			if contains(r.TF.UnknownAttrs, "ingress") {
				g.unknown(r, fmt.Sprintf("Ingress rules of %s are unknown until apply; exposure not assessed", r.Name), r.Src)
			}
			pub := PublicIngress(r)
			if len(pub) == 0 {
				continue
			}
			var ports []string
			for _, ig := range pub {
				ports = append(ports, PortRange(ig))
			}
			g.addEdge(edgeOpt{from: InternetID, to: r.ID, typ: "exposes",
				label: fmt.Sprintf("Internet may connect to security group %s (%s)", r.Name, strings.Join(ports, ", ")),
				conf:  model.Confirmed, evidence: "ingress allows 0.0.0.0/0", src: r.Src, attack: true})

		case model.KindInstance:
			g.instanceEdges(r)

		case model.KindDatabase:
			sgs := append(r.Refs["vpc_security_group_ids"], r.Refs["security_group_ids"]...)
			pa := r.TF.PubliclyAccessible
			for _, sid := range sgs {
				sg := g.byID[sid]
				if sg == nil || len(PublicIngress(sg)) == 0 {
					continue
				}
				if r.TF.Port != 0 {
					ok := false
					for _, ig := range PublicIngress(sg) {
						ok = ok || covers(ig, r.TF.Port)
					}
					if !ok {
						continue
					}
				}
				switch {
				case pa != nil && *pa:
					g.addEdge(edgeOpt{from: sg.ID, to: r.ID, typ: "allows_traffic", label: fmt.Sprintf("%s lets the Internet reach database %s", sg.Name, r.Name),
						conf: model.Confirmed, evidence: "publicly_accessible = true", src: r.Src, attack: true})
				case pa == nil:
					g.unknown(r, fmt.Sprintf("publicly_accessible of %s is unknown at plan time; Internet reachability is not assumed", r.Name), r.Src)
				}
			}

		case model.KindBucket:
			public := r.TF.ACL == "public-read" || r.TF.ACL == "public-read-write"
			blocked := r.TF.PublicAccessBlock != nil && *r.TF.PublicAccessBlock
			if public && !blocked {
				g.addEdge(edgeOpt{from: InternetID, to: r.ID, typ: "exposes", label: fmt.Sprintf("Internet can read bucket %s (ACL %s)", r.Name, r.TF.ACL),
					conf: model.Confirmed, src: r.Src, attack: true})
			}

		case model.KindIdentity:
			if r.Type == "aws_iam_instance_profile" {
				for _, rid := range r.Refs["role"] {
					if g.byID[rid] != nil {
						g.addEdge(edgeOpt{from: r.ID, to: rid, typ: "uses_role", label: fmt.Sprintf("Instance profile %s carries role %s", r.Name, g.byID[rid].Name),
							conf: model.Confirmed, src: r.Src, attack: true})
					}
				}
			}
			if r.Type == "aws_iam_role" {
				stmts, sources := g.RoleStatements(r)
				for _, c := range IAMCapabilities(stmts) {
					capID := "cap:aws:" + c.key
					g.ensure(&model.Resource{ID: capID, Domain: model.DomainTerraform, Kind: model.KindCapability, Type: "Capability",
						Name: c.name, Sensitive: true, SensitiveReason: c.reason, Attrs: map[string]any{"weight": c.weight, "capability": c.key}})
					src := r.Src
					for _, pid := range r.Refs["policies"] {
						if p := g.byID[pid]; p != nil {
							src = p.Src
							break
						}
					}
					g.addEdge(edgeOpt{from: r.ID, to: capID, typ: "grants", discrim: c.key,
						label: fmt.Sprintf("Role %s grants: %s", r.Name, c.reason), conf: model.Confirmed,
						evidence: "policies: " + strings.Join(sources, ", "), src: src, attack: true})
				}
			}
		}
	}
}

func (g *Graph) instanceEdges(r *model.Resource) {
	pub := r.TF.PublicIP
	sgs := append(append([]string(nil), r.Refs["vpc_security_group_ids"]...), r.Refs["security_groups"]...)
	if pub == nil {
		if len(sgs) > 0 {
			g.unknown(r, fmt.Sprintf("Public IP assignment of %s cannot be determined from the plan (depends on subnet defaults); Internet reachability is inferred, not confirmed", r.Name), r.Src)
		}
	}
	for _, sid := range sgs {
		sg := g.byID[sid]
		if sg == nil || len(PublicIngress(sg)) == 0 {
			continue
		}
		switch {
		case pub != nil && *pub:
			g.addEdge(edgeOpt{from: sg.ID, to: r.ID, typ: "allows_traffic", label: fmt.Sprintf("%s forwards Internet traffic to %s", sg.Name, r.Name),
				conf: model.Confirmed, evidence: "associate_public_ip_address = true", src: r.Src, attack: true})
		case pub == nil:
			g.addEdge(edgeOpt{from: sg.ID, to: r.ID, typ: "allows_traffic", label: fmt.Sprintf("%s may forward Internet traffic to %s", sg.Name, r.Name),
				conf: model.Inferred, conds: []string{"The instance has a public IP or sits behind a public load balancer (not determinable from the plan)"},
				src: r.Src, attack: true})
		}
	}
	for _, pid := range r.Refs["iam_instance_profile"] {
		if g.byID[pid] == nil {
			continue
		}
		conds := []string{conditionCompromise, "Role credentials are retrievable from the instance metadata service (IMDS)"}
		if r.TF.HTTPTokens == "required" {
			conds = append(conds, "IMDSv2 is enforced, so exploitation needs a full request-forgery primitive rather than a simple SSRF")
		}
		g.addEdge(edgeOpt{from: r.ID, to: pid, typ: "assumes", label: fmt.Sprintf("%s can obtain credentials of instance profile %s", r.Name, g.byID[pid].Name),
			conf: model.Conditional, conds: conds, src: r.Src, attack: true})
	}
}
