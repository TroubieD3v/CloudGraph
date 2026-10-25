# Terraform support matrix

CloudGraph reads the output of `terraform show -json plan.out` and models **a fixed subset of AWS resources**. It is
not a general analyser for any Terraform plan. A resource type that is not listed below is counted, reported in the
import warnings and in `pathSearch.coverage.unmodelledTypes`, and left out of the graph. **No attack path can run
through a resource that is not modelled**, so an empty result means "nothing found among the modelled resources",
not "nothing exists".

Everything else about a plan follows the same rules as the other inputs: line numbers are kept, secrets are masked
at import, and values that are unknown until `apply` become *Unknown* notes instead of assumed connections.

## Modelled resources

| Resource type | Role in the graph | Used by |
|---|---|---|
| `aws_security_group` | Firewall. Inline `ingress` rules; `0.0.0.0/0` and `::/0` make it an Internet entry point | CG-TF-001, paths |
| `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule` | Merged into their security group when it is in the plan, otherwise kept as a standalone firewall | CG-TF-001, paths |
| `aws_instance` | Instance: public IP, IMDS tokens, root volume encryption, security groups, instance profile | CG-TF-001, 007, 008, 011, paths |
| `aws_iam_instance_profile` | Identity linking an instance to its role | paths |
| `aws_iam_role` | Identity: inline policies and managed policy ARNs become capabilities (see below) | CG-TF-005, 010, paths |
| `aws_iam_policy` | Policy statements, attached to roles through references | CG-TF-005, 010, paths |
| `aws_iam_role_policy`, `aws_iam_role_policy_attachment` | Folded into the role they belong to | CG-TF-005, 010, paths |
| `aws_s3_bucket` | Bucket: ACL, `bucket` name, sensitivity tag; public ACLs are an Internet entry point | CG-TF-002, 003, paths |
| `aws_s3_bucket_public_access_block`, `aws_s3_bucket_acl`, `aws_s3_bucket_server_side_encryption_configuration` | Folded into the bucket | CG-TF-002, 003 |
| `aws_db_instance` | Database (always a sensitive target): public accessibility, encryption, port, security groups | CG-TF-006, 007, 011, paths |

Data sources (`mode = "data"`) are ignored. Resources inside modules are included, with their module prefix.

### What the IAM model understands

Capabilities are derived from policy statements and from these AWS-managed policies, matched by name:
`AdministratorAccess`, `IAMFullAccess`, `AmazonS3FullAccess`, `AmazonS3ReadOnlyAccess`, `SecretsManagerReadWrite`.
Statements are evaluated for `Allow` effects on wildcard resources only; `Deny` statements, conditions, permission
boundaries, service control policies and trust (assume-role) policies are **not** evaluated.

## Not modelled

These are the most common gaps; the list is not exhaustive.

| Area | Examples | Consequence |
|---|---|---|
| Networking | `aws_vpc`, `aws_subnet`, route tables, NACLs, gateways, VPC endpoints | Reachability is derived from security groups alone; subnet defaults are an Unknown note |
| Load balancing and edge | `aws_lb`, `aws_alb`, CloudFront, API Gateway, WAF | An instance behind a load balancer is treated as *possibly* public, never confirmed |
| Compute platforms | EKS, ECS, Lambda, Auto Scaling, Launch Templates | No paths through functions, containers or node groups defined in Terraform |
| Identity | `aws_iam_user`, groups, access keys, SSO, cross-account trust | Only instance-profile roles are followed |
| Data and secrets | bucket policies, KMS keys, Secrets Manager, SSM, DynamoDB, other databases (Aurora clusters, ElastiCache) | Only `aws_db_instance` and `aws_s3_bucket` are sensitive targets |
| Other providers | Google Cloud, Azure, Kubernetes/Helm providers | Not imported from Terraform; use the Kubernetes YAML input for manifests |

## Reading the result

A scan tells you what it covered:

- `pathSearch.coverage.unmodelledTypes`: input resources by type that were skipped;
- `pathSearch.coverage.resourceKinds` and `edgeTypes`: what the search worked with;
- `pathSearch.searchComplete` and `pathSearch.scopeLimited`: whether a limit stopped the search or left routes out
  (see the README, *Search limits*).

The importer's list of supported types lives in `parse.TerraformTypes`; a test keeps this page in sync with it.
To request a resource type, open an issue with a minimal plan JSON that contains it.
