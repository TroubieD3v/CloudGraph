package rules

import (
	"fmt"
	"strings"

	"github.com/TroubieD3v/cloudgraph/internal/graph"
	"github.com/TroubieD3v/cloudgraph/internal/mask"
	"github.com/TroubieD3v/cloudgraph/internal/model"
)

func init() {
	tf := model.DomainTerraform

	register(Rule{
		ID: "CG-TF-001", Title: "Security group open to the Internet on a sensitive port", Severity: model.SevCritical, Domain: tf, Kinds: []string{model.KindFirewall},
		Remediation: "Restrict ingress to known CIDR ranges, a bastion, or use SSM Session Manager instead of exposing management ports.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			var out []Draft
			for i, ig := range graph.PublicIngress(r) {
				var hits []string
				if ig.Protocol == "-1" {
					hits = append(hits, "all ports")
				} else {
					for p, name := range adminPorts {
						if p >= ig.From && p <= ig.To {
							hits = append(hits, fmt.Sprintf("%d (%s)", p, name))
						}
					}
				}
				if len(hits) == 0 {
					continue
				}
				out = append(out, Draft{Key: fmt.Sprint(i), Path: "ingress",
					Message: fmt.Sprintf("Security group %s allows %s from 0.0.0.0/0 to %s.", r.Name, graph.PortRange(ig), strings.Join(sortedStrings(hits), ", ")),
					Fix:     newFix("tf_restrict_cidr", r.ID, "Restrict public ingress of "+r.Name+" to a trusted CIDR (e.g. 10.0.0.0/8)", map[string]any{})})
			}
			return out
		},
	})

	register(Rule{
		ID: "CG-TF-002", Title: "S3 bucket allows public access", Severity: model.SevHigh, Domain: tf, Kinds: []string{model.KindBucket},
		Remediation: "Use a private ACL and enable all four S3 Public Access Block settings.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			blocked := r.TF.PublicAccessBlock != nil && *r.TF.PublicAccessBlock
			if (r.TF.ACL == "public-read" || r.TF.ACL == "public-read-write") && !blocked {
				return []Draft{{Path: "acl", Message: fmt.Sprintf("Bucket %s has ACL %q and no complete public access block.", r.Name, r.TF.ACL),
					Fix: newFix("tf_private_bucket", r.ID, "Make bucket "+r.Name+" private and enable the public access block", map[string]any{})}}
			}
			return nil
		},
	})

	register(Rule{
		ID: "CG-TF-003", Title: "S3 bucket has no public access block in this plan", Severity: model.SevLow, Domain: tf, Kinds: []string{model.KindBucket},
		Remediation: "Add aws_s3_bucket_public_access_block (or enforce it at account level).",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if r.TF.PublicAccessBlock == nil {
				return []Draft{{Path: "public_access_block",
					Message: fmt.Sprintf("Bucket %s has no aws_s3_bucket_public_access_block in the plan. An account-level block may still apply; it is not visible here.", r.Name)}}
			}
			return nil
		},
	})

	register(Rule{
		ID: "CG-TF-005", Title: "IAM policy grants administrator access", Severity: model.SevCritical, Domain: tf, Kinds: []string{model.KindPolicy, model.KindIdentity},
		Remediation: "Replace Action \"*\" / Resource \"*\" with the minimum set of actions and ARNs.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			stmts := r.TF.Statements
			if r.Type == "aws_iam_role" {
				stmts, _ = c.G.RoleStatements(r)
				// avoid double reporting: attached policies are reported on the policy itself
				stmts = r.TF.Statements
				for _, arn := range r.TF.ManagedARNs {
					if strings.HasSuffix(arn, "/AdministratorAccess") {
						return []Draft{{Path: "managed_policy_arns", Message: fmt.Sprintf("Role %s has the AWS managed AdministratorAccess policy attached.", r.Name),
							Fix: newFix("tf_remove_admin", r.ID, "Detach AdministratorAccess from "+r.Name, map[string]any{})}}
					}
				}
			}
			for _, st := range stmts {
				if st.Effect == "Allow" && model.HasExact(st.Actions, "*") && model.HasExact(st.Resources, "*") {
					return []Draft{{Path: "policy", Message: fmt.Sprintf("%s allows every action on every resource.", r.Name),
						Fix: newFix("tf_remove_admin", r.ID, "Replace the wildcard statement in "+r.Name+" with least-privilege actions", map[string]any{})}}
				}
			}
			return nil
		},
	})

	register(Rule{
		ID: "CG-TF-006", Title: "RDS instance is publicly accessible", Severity: model.SevCritical, Domain: tf, Kinds: []string{model.KindDatabase},
		Remediation: "Set publicly_accessible = false and place the instance in private subnets.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if r.TF.PubliclyAccessible != nil && *r.TF.PubliclyAccessible {
				return []Draft{{Path: "publicly_accessible", Message: fmt.Sprintf("Database %s is publicly accessible.", r.Name),
					Fix: newFix("tf_private_db", r.ID, "Set publicly_accessible = false on "+r.Name, map[string]any{})}}
			}
			return nil
		},
	})

	register(Rule{
		ID: "CG-TF-007", Title: "Storage is not encrypted", Severity: model.SevMedium, Domain: tf, Kinds: []string{model.KindDatabase, model.KindInstance},
		Remediation: "Enable storage_encrypted (RDS) / encrypted (EBS root volume) with a KMS key.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if r.TF.Encrypted != nil && !*r.TF.Encrypted {
				return []Draft{{Path: "encrypted", Message: fmt.Sprintf("%s stores data unencrypted.", r.Name)}}
			}
			return nil
		},
	})

	register(Rule{
		ID: "CG-TF-008", Title: "Instance metadata service allows IMDSv1", Severity: model.SevMedium, Domain: tf, Kinds: []string{model.KindInstance},
		Remediation: "Set metadata_options { http_tokens = \"required\" } to enforce IMDSv2.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			if r.TF.HTTPTokens == "required" {
				return nil
			}
			return []Draft{{Path: "metadata_options.http_tokens",
				Message: fmt.Sprintf("Instance %s does not enforce IMDSv2; SSRF in an application can steal the instance role credentials.", r.Name),
				Fix:     newFix("tf_require_imdsv2", r.ID, "Require IMDSv2 on "+r.Name, map[string]any{})}}
		},
	})

	register(Rule{
		ID: "CG-TF-010", Title: "Role can escalate IAM privileges", Severity: model.SevHigh, Domain: tf, Kinds: []string{model.KindPolicy},
		Remediation: "Remove iam:PassRole / iam:Attach* / iam:Put* on Resource \"*\" or scope them to specific ARNs.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			for _, st := range r.TF.Statements {
				if st.Effect != "Allow" || !hasWide(st.Resources) || model.HasExact(st.Actions, "*") {
					continue
				}
				for _, a := range st.Actions {
					la := strings.ToLower(a)
					if la == "iam:*" || la == "iam:passrole" || strings.HasPrefix(la, "iam:attach") || strings.HasPrefix(la, "iam:put") || la == "iam:createaccesskey" || la == "iam:createpolicyversion" || la == "iam:updateassumerolepolicy" {
						return []Draft{{Path: "policy", Message: fmt.Sprintf("%s allows %s on all resources, which can be abused to gain administrator rights.", r.Name, a),
							Fix: newFix("tf_remove_admin", r.ID, "Scope IAM write actions in "+r.Name, map[string]any{})}}
					}
				}
			}
			return nil
		},
	})

	register(Rule{
		ID: "CG-TF-011", Title: "Plaintext secret present in plan", Severity: model.SevMedium, Domain: tf, Kinds: []string{model.KindDatabase, model.KindInstance},
		Remediation: "Do not pass passwords or user_data secrets as literals; use manage_master_user_password, Secrets Manager or SSM. Plan and state files contain these values in clear text.",
		Check: func(c *Ctx, r *model.Resource) []Draft {
			vals, _ := r.Attrs["values"].(map[string]any)
			for k, v := range vals {
				if s, ok := v.(string); ok && s == mask.Redacted && (strings.Contains(strings.ToLower(k), "password") || k == "user_data") {
					return []Draft{{Key: k, Path: k, Message: fmt.Sprintf("%s sets %s to a literal value (masked by CloudGraph before storage).", r.Name, k)}}
				}
			}
			return nil
		},
	})
}

func hasWide(res []string) bool {
	for _, r := range res {
		if r == "*" {
			return true
		}
	}
	return false
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
