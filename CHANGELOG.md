# Changelog

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
