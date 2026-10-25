# Changelog

## 0.3.0

- "Complete" is now two answers. `pathSearch.searchComplete`: no depth or candidate limit stopped the search.
  `pathSearch.scopeLimited`: any limit, **including `--max-pivots`**, left routes out. Before, a client that read
  only `complete` could take a result that skipped multi-pivot chains for a full one. `complete` stays as the old
  name of `searchComplete`. Stored snapshots from earlier versions are read as before.
- `pathSearch.coverage`: resources by kind, the relationship types the search could follow, undecided relationships
  it never follows, and input resource types that are not modelled (`unmodelledTypes`).
- The pivot notice is now **Limited coverage** and says that paths needing more pivots are not in the result. The
  terminal and HTML reports start with a `Search:` line; the web UI shows "search complete · limited coverage" and a
  coverage panel.
- `--fail-limited` exits 1 when any limit left routes out (`--fail-incomplete` keeps meaning a stopped search).
- Alternative paths: routes merged into one path are counted in `similarRoutes`; `--alternatives`,
  `limits.showAlternatives`, `GET /api/analyses/{id}?alternatives=1` and the **Show alternative paths** switch in the
  overview list them with their own preconditions (up to 10 per path). The representative path does not change.
- Public [Terraform support matrix](docs/terraform-support.md): the modelled AWS subset and the known gaps. A test
  keeps it in sync with the importer.
- Tests: a fixture whose only dangerous chain needs two network pivots, checked with one and two pivots.
- CI and `make test` run `go test -race ./...`.

## 0.2.0

- Redesigned web interface: palette Primary #121212, Secondary #008542, Tertiary #D97706, Neutral #64748B; Manrope
  headlines and Inter text; square buttons and inputs, rounded cards, a pill navigation (bottom bar on phones).
- Dark theme by default with a light theme toggle in the top bar; the choice is remembered. The graph, minimap and
  edge colours follow the theme.
- Overview: hero with a two-ring dial (exposure and fixable findings), posture, the top path expanded and the others
  as compact cards, a "fix this first" suggestion from the biggest shared choke point.
- Findings as cards with kind icons; what-if with switches, impact per fix and a summary card; diff with a
  before/after chart per metric; unknowns as cards.
- Fonts (Manrope, Inter) and icons (Lucide) are bundled into the binary; no external requests.
- HTML report restyled with the same palette.
- New screenshots and demo GIF, including the light theme.

## 0.1.0

- Import: Docker Compose (services, networks, ports, volumes, secrets, `depends_on`), Kubernetes YAML (Pod
  controllers, Services, Ingress, ServiceAccounts, Roles and bindings, NetworkPolicy, Secrets, `List`), Terraform
  plan JSON for an AWS subset (security groups including standalone ingress rules, EC2, IAM, S3, RDS), modules
  included. Line numbers are kept; secrets are masked at import.
- Graph engine with per-edge source, confidence (`confirmed`, `inferred`, `conditional`, `unknown`) and conditions;
  RBAC and NetworkPolicy semantics; Unknown notes instead of invented connections.
- 41 rules with positive and negative tests; generated reference in `docs/RULES.md`.
- Attack path engine: Internet-reachable entry to sensitive target, risk score, prerequisites, shared choke points.
  Among routes to the same target the best supported one is kept (strongest weakest step, then fewer unconfirmed
  steps, then length), so a short conditional route never hides a longer confirmed one.
- Configurable search limits (`--max-depth`, `--max-paths`, `--max-pivots`, `limits` in the API) recorded with each
  analysis. Reaching the depth or candidate limit marks the result as incomplete in the terminal, HTML, UI and
  SARIF notifications; `--fail-incomplete` fails a pipeline on partial results. What-if reuses the original limits.
- What-if simulator on a virtual copy; patch export for `git apply --unidiff-zero`, verified by re-scanning the
  patched demos.
- Infrastructure diff by relationships, findings and paths.
- Reports: terminal, JSON, HTML, SARIF 2.1.0 with attack paths as code flows; `--fail-on` exit codes. CI checks
  that the vulnerable demos fail the gate and produce schema-valid SARIF with findings and paths.
- Web UI (React, `@xyflow/react`): overview, graph with path highlighting and edge explanations, findings, source
  viewer, what-if, diff, Unknown; report downloads and local history in SQLite.
- Three demo projects embedded in the binary; Docker image; release workflow for five platforms.
- Robustness: fuzz target, mutation test, regression cases for self-referencing YAML anchors.
