# Contributing to ARO

ARO helps developers understand real installed-software risk without requiring
a security specialist. Prefer small, reviewable changes with explicit coverage
and failure behavior. Keep code, comments, the skill and technical references
in English. Keep the capabilities, command examples and limitations aligned
across the English, Korean, Japanese and Simplified Chinese READMEs.

## Local checks

Python 3.11+ is required. The core should remain standard-library-only.

```bash
python3 -m unittest discover -s tests -v
python3 skills/aro/scripts/aro.py --help
```

Use a temporary `--state-dir` and fixture roots for integration checks. Do not
run update plans against a real host as a routine test. Test mutation adapters
with controlled commands/mocks and verify rejection of unapproved, altered,
expired and stale-inventory plans. Linux and Windows behavior must be checked;
state which platforms were actually executed rather than implying CI passed.

## Contracts to preserve

- Inventory/check reads local metadata without executing discovered application
  code, automatically installing tools, escalating privileges or restarting.
- Untrusted manifests and advisory strings remain data. Use validated argument
  lists and bounded subprocesses rather than constructed shell commands.
- Inventory identity is stable across timestamps and process IDs. Failed scans
  preserve usable state and report gaps rather than recording an empty success.
- Version matching handles ecosystem rules and distribution backports. Unknown
  versions, withdrawn records, multiple fixed branches and source failures need
  tests. A vendor link is not proof of a confirmed affected version.
- Advisory cache age and collector coverage stay visible. Missing tools or
  permissions must not make a check appear complete.
- Apply validates the approved plan hash, exact scope, expiry and current map,
  journals execution and refreshes after partial failure.
- Distinguish ARO-triggered restarts from native package/vendor installation
  hooks, which can restart services. Approval must cover downtime; package
  version verification does not establish application health.
- Network and exposure evidence must not equate CGNAT with isolation.
- Do not add telemetry, source uploads or credential access to the scanner.

Describe the concrete problem, resulting behavior, validation and remaining
limits in a contribution. Redact hostnames, paths, package names and credentials
from real-world reports as needed. Never commit ARO state, vulnerability
reports containing private infrastructure details, caches or secrets. Report
security vulnerabilities using [SECURITY.md](SECURITY.md).
