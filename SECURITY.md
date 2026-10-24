# Security policy

## Reporting a vulnerability in CloudGraph

Please do not open a public issue for security problems in CloudGraph itself (for example a secret that survives
masking and reaches a report, the database or the source viewer, a crafted configuration that crashes or hangs the
engine, or a way to drive the local web service from another origin). Use GitHub's private vulnerability reporting on
<https://github.com/TroubieD3v/CloudGraph/security/advisories/new> instead.

Include the version (`cloudgraph version`), a minimal input file and steps to reproduce. You will get an answer
within a week.

## Using CloudGraph responsibly

CloudGraph is a static analyser: its paths are hypotheses that need the listed preconditions, not proof of an
exploitable system. Do not expose `cloudgraph serve` to a network: it has no authentication by design and is meant
to run on `127.0.0.1`.

The demo projects in `examples/` are insecure on purpose. Do not deploy them.
