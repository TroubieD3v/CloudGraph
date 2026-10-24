# Architecture

```
files ──► parse ──► inventory ──► graph ──► rules ──► paths ──► analysis ──► CLI / API / UI / reports
                                    ▲                                  │
                                    └──────── what-if (clone + fixes) ◄┘
```

## Stages

| Stage | Package | Output |
|---|---|---|
| Import | `internal/parse` | A `Resource` per object with `Source{file, line}` and normalised specs (workload, RBAC, NetworkPolicy, Terraform facts); secrets are masked here |
| Graph | `internal/graph` | `Edge{from, to, type, confidence, conditions, evidence, source}` and `UnknownNote`s; synthetic nodes for the Internet, hosts and capabilities |
| Rules | `internal/rules` | `Finding`s with remediation and an optional `Fix` (model action plus line edits) |
| Paths | `internal/paths` | `Path`s with steps, prerequisites, score and severity; hotspots |
| Analysis | `internal/analyze` | A serialisable snapshot; what-if, patch export and diff work on snapshots |

## Graph semantics

- **Kubernetes**: Internet → Ingress / LoadBalancer / NodePort Service → the Service selects pods by labels → the
  pod runs as a ServiceAccount (an attack edge only if the token is mounted) → bound by a RoleBinding or
  ClusterRoleBinding → capability (`secrets-read`, `pod-exec`, `workload-create`, `rbac-escalation`, `admin`) scoped
  to a namespace or the cluster. Container escape (privileged, runtime socket, sensitive hostPath, `hostPID` with
  ptrace, escape-capable capabilities) leads to the node. Lateral movement to pivot-worthy pods follows NetworkPolicy
  evaluation.
- **Docker Compose**: ports published on all interfaces are exposure; shared networks, `depends_on` and host names in
  environment values are reachability; escape reasons lead to the Docker host.
- **Terraform (AWS)**: a security group open to `0.0.0.0/0` → the instance or database it protects → instance
  profile → role → account-level capability derived from the attached policies (admin, IAM escalation, secrets, S3
  data).

## Paths

Depth-first search from the Internet over attack edges, never over Unknown, stopping at sensitive nodes, with at most
one network pivot. The best candidate per (first compromised resource, last hop, target) is kept. Score = target
weight × confidence factor (confirmed 1.0, inferred 0.92, conditional 0.85), minus a small penalty for long paths.

## What-if and patches

A snapshot is turned back into an inventory (synthetic nodes dropped) and cloned, fixes are applied as model actions,
and the whole pipeline runs again; paths are matched by signature. Fixes with mechanical edits are exported as a
zero-context unified diff; the others are listed as manual steps.

## Storage and UI

The server keeps snapshots in SQLite (`internal/store`) and serves the React UI embedded from
`internal/ui/dist/app`. The UI uses `@xyflow/react` with a dagre layout and talks to the REST API only.
