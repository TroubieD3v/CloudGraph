# Contributing

```bash
make build            # UI + binary
go vet ./... && go test -race ./...
npm --prefix web run test:e2e
```

## Adding a rule

A rule lives in `internal/rules/` (`compose.go`, `k8s.go` or `terraform.go`) and is registered in `init()`:

- `Check(ctx, resource) []Draft` returns one draft per violation with the **exact line** (`resource.Loc(...)`,
  container `Locs`) and a message that names the resource. Never put a secret value into the message.
- Attach a `Fix` when the remediation can be applied to the model (`internal/analyze/whatif.go`). Add `Edits` only
  when the change is mechanical and safe; otherwise the fix is listed as a manual step.

Every rule needs:

1. a positive example: it must fire on `demo:vulnerable-all` or on `internal/rules/testdata/`;
2. a negative case: the hardened demo must stay clean, and a near-miss belongs in `TestNegativeCases`;
3. a regenerated reference: `go run ./cmd/cloudgraph rules --format markdown > docs/RULES.md`.

## Adding graph semantics

New edges go into `internal/graph/`. Each edge must carry a source line, a confidence level and the conditions it
depends on. If the input cannot decide a relationship, emit an Unknown note (`g.unknown`) instead of an edge, and add
a test in `internal/graph/graph_test.go` proving that no edge is invented.
