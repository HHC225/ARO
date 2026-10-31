# ARO design

## Intent

Build an installable agent skill for people who develop and operate applications without a security specialist. On every invocation, inventory the current Linux or Windows server, reconcile a persistent local software map, query only relevant advisory sources, explain practical risk briefly, and offer a reviewable patch plan. Execute a patch only after explicit approval and refresh the map afterward.

## Decisions

- A Python 3.11+ standard-library engine, with Bash and PowerShell launchers, provides the same JSON contracts on both platforms. These are implementation decisions based on the user's requested portability.
- The repository is the distribution artifact: `skills/aro/` is independently installable. No ChatGPT-only installation is required.
- Inventory is local and read-only. Never execute repository build scripts, import discovered Python packages, install scanners, elevate privileges, or run arbitrary commands from advisory content during a check.
- Native inventory covers OS/package managers, runtimes, processes, listeners, manifests/lockfiles and Docker metadata. Optional Syft deepens SBOM coverage; optional Trivy handles distribution-aware host/container vulnerabilities. Missing tools, permissions, and unresolved versions are recorded as coverage gaps.
- Advisory requests send package coordinates and versions, not source code, file contents, credentials, hostnames, or private paths. A configurable package exclusion list is supported. All fetched material is untrusted data.
- OSV supplies ecosystem advisories (including records without CVE identifiers); CISA KEV adds exploitation context; vendor/distro sources supply OS-specific evidence; runtime-maintainer advisory sources supplement language packages. Never compare distro backport versions with upstream semantic versions.
- A stable inventory fingerprint excludes timestamps and volatile process IDs. Refresh on every check; record additions, removals, version changes, evidence and coverage changes. Never silently delete the last usable map on a failed scan.
- CGNAT and private addresses are evidence about one route, not proof of isolation. IPv6, tunnels, reverse proxies, forwarding, local network access, user interaction and local privilege escalation remain relevant. Unknown exposure remains unknown.
- Use short reports: affected component, installed version, patch information, practical priority, one-sentence reason, source links and coverage freshness. Store technical detail locally in JSON.
- Patches use a bounded plan with exact arguments, snapshot hash, expiry and plan hash. Apply requires explicit plan approval, verifies unchanged inventory, runs allowlisted adapters, journals results, then re-inventories even after partial failure. No automatic reboot or service restart. Manual instructions remain available when automated patching is unsafe or unsupported.

## Alternatives considered

1. LLM web-search-only workflow: small implementation but inconsistent records and unavailable when browsing is disabled; unsuitable for the user's deterministic requirement.
2. Shell/PowerShell implementations of the entire system: no shared runtime but duplicate parsers, matching and state logic; harder to keep consistent.
3. Shared Python engine plus OS launchers and existing scanner adapters: selected for consistent behavior and explicit coverage; Python is a documented prerequisite.

## State contract

State lives outside the skill, by default under the user's platform-local state directory. Atomic JSON files use schema version 1. `inventory.json` is the current map, `report.json` the last check, `plans/` immutable patch plans, `cache/` advisory responses, and `history/` patch journals. A lock prevents concurrent modification. Local state is never committed.

Inventory fields: `schema_version`, `scanned_at`, `host` (OS id/version/architecture), `roots`, `components`, `projects`, `containers`, `network`, `coverage`. Components contain `id`, `name`, `version`, `ecosystem` (OSV name or null), `kind`, `source`, `path`, and optional `purl`, `manager`, `scope`, `metadata`. Stable IDs identify an installation independently of its version. Coverage entries contain `collector`, `status` (`ok`, `partial`, `unavailable`, `error`, or `skipped`) and `detail`.

Advisory contract: `id`, `aliases`, `component_id`, `source`, `source_url`, `summary`, `severity`, `cvss_score` (nullable), `attack_vector` (`network`, `adjacent`, `local`, `physical`, or `unknown`), `fixed_versions`, `affected_range`, `published`, `modified`, `known_exploited`, `match_confidence`, and optional `references`. Missing version evidence is never a confirmed match. Multiple fixed branches remain separate; no lexical version comparison.

## Acceptance and limitations

Prove first-run creation, repeat-run unchanged detection, changed/new/removed software, partial scans, failed/stale sources, paginated responses, withdrawn advisories, multiple fixed branches, CGNAT/tunnel/IPv6 cases, patch rejection without approval, tampered/stale plans, failed patches and post-patch refresh. Run native Linux smoke tests and a Linux/Windows CI matrix. Document exactly what was executed. Full discovery of every custom binary and external router/firewall policy is not promised; unknowns are visible.
