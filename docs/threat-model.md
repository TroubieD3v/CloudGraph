# Threat model

CloudGraph reads configuration that often contains credentials and runs a local web service. The main risks are
therefore *leaking secrets from the input*, *being crashed or stalled by hostile input*, *someone else driving the
local service* and *misleading the user with false certainty*.

| Threat | Mitigation |
|---|---|
| Secrets in the input reach storage, reports, logs or the UI | Masking at import, before the inventory exists: secret-looking env values, credentials in URLs, Terraform `sensitive_values`, all Kubernetes Secret data (only key names kept); the source viewer and patch context use masked lines; a test checks every output format for planted secrets |
| Hostile or corrupted configuration crashes or stalls the engine | Self-referencing YAML anchors and nested `List`s are bounded; path search has depth and result limits; uploads are capped at 16 MiB; a fuzz target and a mutation test are part of the suite |
| Another website or local user drives the API (CSRF, DNS rebinding) | Binds to `127.0.0.1` by default and warns on other addresses; cross-origin writes rejected by `Origin`; only `application/json` bodies accepted; strict CSP and `X-Frame-Options: DENY`; the Docker port is published on loopback |
| Path traversal through uploaded file names | Names containing `..` are rejected; uploads are kept in memory and never written to disk |
| False confidence from a clean result | Every edge carries a confidence level; unresolved references are listed in the Unknown view; absence of a NetworkPolicy is reported as hedged, never as confirmed |
| False alarms that hide real paths | A path needs an Internet-reachable entry and a sensitive target and allows at most one network pivot; the hardened demo must produce zero findings and zero paths |
| A proposed patch breaks the configuration | Patches are zero-context diffs for review and are never applied automatically; a test applies them to the demos and re-scans the result |

## Out of scope

- CloudGraph sees only the files it is given. Policies, RBAC objects or security groups defined elsewhere can change
  the real picture; that is why such cases are hedged or reported as Unknown.
- NetworkPolicy enforcement depends on the cluster's CNI plugin, which configuration files do not reveal.
- The local service trusts the machine it runs on and has no user accounts.
- The demo projects are insecure by design and must never be deployed.
