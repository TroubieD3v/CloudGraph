# CloudGraph

**Offline infrastructure attack path analysis.**
CloudGraph reads your Docker Compose, Kubernetes and Terraform configuration, builds a directed graph of the resources and their relationships, and explains how individually small weaknesses can chain into a dangerous path — without ever connecting to a cloud account.

> Example: *if the exposed web app is compromised, the over-privileged ServiceAccount it runs as can read every Kubernetes Secret.*

A path is **conditional**. CloudGraph never claims that an application can actually be hacked; it shows which preconditions must hold, where each step comes from (file and line), and how confident the engine is.

![Overview with conditional attack paths](docs/screenshots/overview.png)

## Why not just a linter?

| IaC linter | CloudGraph |
| --- | --- |
| "This container is privileged" | "…and it is reachable from the Internet through this Ingress, so a bug in the app could mean node takeover" |
| Lists problems | Shows **chains** and the shared choke points that break several chains at once |
| "Fix these 30 findings" | **What-if simulator**: which fix removes which paths, before you touch a file |
| Silent when data is missing | Reports **Unknown** instead of inventing a connection |

## Features

- **Import** Docker Compose, Kubernetes YAML (multi-document, `List`), Terraform plan JSON (`terraform show -json`).
- **Resource graph** with confidence per edge: `confirmed` (stated in config), `inferred` (label selectors, shared networks, NetworkPolicy evaluation), `conditional` (needs an attacker precondition), `unknown` (never traversed).
- **41 security rules** (Compose, Kubernetes incl. RBAC, Terraform/AWS), each with positive and negative tests, source line, remediation and — where possible — a machine-applicable fix. Full list: [docs/RULES.md](docs/RULES.md).
- **Attack path engine** with prerequisites, a risk score (impact × confidence) and hotspot detection.
- **What-if remediation**: virtually apply fixes, recompute the graph, export a `git apply`-able patch. Real files are never modified.
- **Infrastructure diff**: compare two states by relationships, findings and attack paths — not just counts.
- **Reports**: terminal, JSON, HTML, **SARIF 2.1.0** (findings plus attack paths as `codeFlows`) for GitHub Code Scanning.
- **Web UI** (React + `@xyflow/react`): interactive graph with path highlighting, edge explanations, source viewer, findings, what-if, diff. Embedded in the single Go binary.
- **Offline-first**: history is stored in a local SQLite file; nothing leaves your machine.

## Quick start

Download a binary from the Releases page (Linux, macOS, Windows; single file, no dependencies), or build it:

```bash
make build                      # builds the UI and bin/cloudgraph (needs Go and Node.js)
./bin/cloudgraph serve          # http://127.0.0.1:8080
```

With Docker:

```bash
docker build -t cloudgraph --build-arg VERSION=dev .
docker run --rm -p 127.0.0.1:8080:8080 -v cloudgraph-data:/data cloudgraph
docker run --rm -v "$PWD/infrastructure:/in:ro" cloudgraph scan /in --format sarif
```

Or with the CLI only:

```bash
go run ./cmd/cloudgraph scan demo:insecure-kubernetes
go run ./cmd/cloudgraph scan ./infrastructure --format sarif --output results.sarif
```

Bundled demo projects (`cloudgraph demos`):

| Demo | Story |
| --- | --- |
| `vulnerable-ecommerce` | Compose shop with a public frontend, privileged backend with `docker.sock`, exposed databases + an AWS plan with an open security group and an admin instance role |
| `insecure-kubernetes` | Namespaces, ServiceAccounts, cluster-wide RBAC, a privileged workload behind a LoadBalancer, a database without NetworkPolicy |
| `hardened-infrastructure` | The same stack, fixed. No findings, no paths — use it for diffs |

## CLI

```text
cloudgraph scan <path|demo:NAME>... [--format table|json|sarif|html] [--output FILE] [--fail-on SEVERITY]
cloudgraph simulate <path|demo:NAME>... (--list | --fix ID,ID | --all) [--patch FILE]
cloudgraph diff <A> <B>
cloudgraph serve [--addr 127.0.0.1:8080] [--db cloudgraph.db]
cloudgraph rules [--format table|markdown]
cloudgraph version
```

```bash
cloudgraph simulate ./k8s --list                       # which fix resolves how many paths?
cloudgraph simulate ./k8s --all --patch fixes.patch    # proposed patch, review then:
git apply --unidiff-zero fixes.patch
cloudgraph diff ./before ./after
```

Exit codes: `0` ok, `1` a finding at or above `--fail-on`, `2` error.

### GitHub Actions

```yaml
- run: cloudgraph scan ./infrastructure --format sarif --output results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Screens

| Graph with a highlighted path and explained edges | What-if: one fix, four chains gone, patch ready |
| --- | --- |
| ![Graph](docs/screenshots/graph.png) | ![What-if](docs/screenshots/whatif.png) |

## How it works

```
 Compose / K8s YAML / Terraform plan JSON
            │  parse (yaml.v3 nodes keep line numbers; secrets masked immediately)
            ▼
   Resource inventory ──► Graph builder ──► Rules ──► Path engine
                          (edges carry source,       (findings +      (DFS from Internet to
                           confidence, conditions)    fixes)           sensitive targets)
            │
            ▼
   Analysis snapshot ──► CLI / REST API (SQLite) / React UI / SARIF
                              ▲
                  What-if: clone inventory → apply fix → re-run everything → diff
```

### Honesty rules

- **Unknown, not guessed.** An Ingress pointing to a Service that is not in the input, a Service whose selector matches nothing, a NetworkPolicy using `ipBlock` or `matchExpressions`, a binding to a role that is not provided, a Terraform value unknown until apply — all become *Unknown* notes and are never traversed.
- **Absence of a NetworkPolicy** is treated as Kubernetes does (allow by default) but is reported as a conditional, hedged edge: the input may be incomplete and enforcement depends on the CNI plugin.
- **No "everything is a path".** A path needs an Internet-reachable entry and a sensitive target, and at most one network pivot — the normal frontend → backend → database architecture is not reported.
- **Secrets are masked at import** (env values, URL credentials, Terraform sensitive values, Kubernetes Secret data) — before the inventory is built, stored, logged or exported. The source viewer and patches use masked lines.

## Layout

```
cmd/cloudgraph      CLI and server entry point
internal/parse      Compose, Kubernetes, Terraform importers
internal/graph      Relationship graph, NetworkPolicy and RBAC semantics
internal/rules      Security rules (+ testdata)
internal/paths      Attack path search and scoring
internal/analyze    Pipeline, what-if simulator, patch export, diff
internal/report     JSON, HTML, SARIF, terminal output
internal/server     REST API;  internal/store  SQLite snapshots
internal/mask       Secret masking
web/                React UI and Playwright tests
examples/           Demo projects (embedded into the binary)
```

## Development

```bash
go vet ./... && go test ./...         # engine, rules, API
npm --prefix web ci && npm --prefix web run build
npm --prefix web run test:e2e          # Playwright; set PW_CHANNEL=chrome to use an installed Chrome
```

Test strategy:

- parser unit tests (line numbers, masking, Terraform references across modules);
- every rule must fire on a vulnerable example, and the hardened project must produce zero findings and zero paths;
- graph tests for Unknown / NetworkPolicy / RBAC semantics — no invented connections;
- the exported patch is applied to the demo files and re-scanned: the result must match the what-if prediction;
- "no secret ever appears in any output" (JSON, SARIF, HTML, terminal, patches, source viewer);
- SARIF structure, API tests (CSRF, malformed input, empty collections), Playwright end-to-end tests;
- robustness: a deterministic mutation test plus `go test ./internal/analyze -run '^$' -fuzz FuzzAnalyze` (self-referencing YAML anchors are a regression case).

`docs/RULES.md` is generated (`cloudgraph rules --format markdown`) and a test fails if it is stale. Screenshots are regenerated with `web/scripts/screenshots.mjs`.

Releases: pushing a `v*` tag builds static binaries for five platforms with checksums (`.github/workflows/release.yml`).

### REST API

`GET /api/demos`, `POST /api/analyses` (`{"demo":…}` or `{"files":[{"name","content"}]}`), `GET /api/analyses[/{id}]`, `POST /api/analyses/{id}/simulate`, `POST /api/analyses/{id}/patch`, `GET /api/analyses/{id}/report/{json|sarif|html}`, `GET /api/diff?a=&b=`.
The server has no authentication: keep it on loopback (default). Cross-origin writes are rejected.

## Scope and limitations

- Kubernetes: Pod controllers, Services, Ingress, ServiceAccounts, Roles/Bindings, NetworkPolicy, Secrets. Helm/Kustomize must be rendered first (`helm template`, `kustomize build`). CRDs are ignored. Aggregated ClusterRoles are reported as Unknown.
- Terraform: AWS subset (security groups, EC2, IAM roles/policies/profiles, S3, RDS) from plan JSON; other resource types are listed as "not modelled".
- Docker Compose: services, networks, ports, volumes, secrets, `depends_on`.
- Plan JSON contains no line numbers; CloudGraph points to the resource's position in the file and Terraform fixes are described, not auto-patched.
- Static analysis only: no runtime events, vulnerability data or live cloud state.

## License

MIT — see [LICENSE](LICENSE).

## Author

TroubieD3v
