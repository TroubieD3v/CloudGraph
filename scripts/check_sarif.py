"""Validate a CloudGraph SARIF file against the SARIF 2.1.0 schema and sanity-check its content.

    pip install jsonschema
    curl -fsSL -o sarif-schema.json https://json.schemastore.org/sarif-2.1.0.json
    python scripts/check_sarif.py vulnerable.sarif sarif-schema.json --min-findings 50 --min-paths 10

Used in CI on the intentionally vulnerable demo, so a regression that empties or
breaks the SARIF output fails the build instead of passing silently.
"""
from __future__ import annotations

import argparse
import json
import sys

import jsonschema


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif")
    ap.add_argument("schema")
    ap.add_argument("--min-findings", type=int, default=1)
    ap.add_argument("--min-paths", type=int, default=1)
    args = ap.parse_args()

    with open(args.schema, encoding="utf-8") as f:
        schema = json.load(f)
    with open(args.sarif, encoding="utf-8") as f:
        log = json.load(f)

    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(log), key=lambda e: list(e.path))
    for e in errors[:20]:
        print(f"schema: {'/'.join(map(str, e.path))}: {e.message[:300]}")
    if errors:
        print(f"{len(errors)} schema error(s)")
        return 1

    run = log["runs"][0]
    rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    results = run["results"]
    paths = [r for r in results if r["ruleId"] == "CG-PATH"]
    findings = [r for r in results if r["ruleId"] != "CG-PATH"]
    problems = []
    if len(findings) < args.min_findings:
        problems.append(f"only {len(findings)} findings, expected at least {args.min_findings}")
    if len(paths) < args.min_paths:
        problems.append(f"only {len(paths)} attack paths, expected at least {args.min_paths}")
    if any(not r.get("codeFlows") for r in paths):
        problems.append("an attack path result has no codeFlows")
    if any(r["ruleId"] not in rules for r in results):
        problems.append("a result references an undeclared rule")
    if any(not r.get("locations") for r in results):
        problems.append("a result has no location")
    for p in problems:
        print(p)
    print(f"{len(findings)} findings, {len(paths)} attack paths, {len(rules)} rules: {'FAIL' if problems else 'OK'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
