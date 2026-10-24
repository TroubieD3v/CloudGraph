## What changes

<!-- Short description and the issue it closes, e.g. "Closes #12". -->

## Checklist

- [ ] `go vet ./... && go test ./...` passes
- [ ] `npm --prefix web run build` and `npm --prefix web run test:e2e` pass if the UI changed
- [ ] A new rule fires on a vulnerable example, stays silent on the hardened demo, and `docs/RULES.md` is regenerated
- [ ] New graph edges carry source, confidence and conditions; undecidable cases become Unknown
- [ ] No real secrets, hosts or account IDs in code, tests, screenshots or reports
- [ ] README / CHANGELOG updated if behaviour changed
