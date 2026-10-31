# Interpret coverage and practical risk

Inventory is evidence about the accessible host at scan time. It is not a
complete asset database or an active penetration test. Each collector reports
`ok`, `partial`, `unavailable`, `error` or `skipped` with a reason. Read these
statuses alongside the findings.

| Surface | Evidence | Limits to communicate |
| --- | --- | --- |
| Linux OS and packages | OS metadata and installed package-manager records; direct source-aware OSV for mapped Debian/Ubuntu releases; optional Trivy for others | Preserve source/binary identities and vendor backports. Missing source mapping, subscription/EOL channels and third-party packages can remain gaps. Never compare distro revisions to upstream semantic versions. |
| Windows OS | OS/build metadata and read-only Windows Update Agent security-update applicability search | The configured update service/policy determines visibility. Search does not download/install updates and is not a full MSRC product/CVE match. Hidden updates and unsupported/EOL products remain gaps; Windows OS updates are manual. |
| Runtimes | Available runtime/version metadata | Side-by-side installs and private/custom binaries may be missed. |
| Applications | Bounded manifest/lockfile discovery under selected roots | A manifest range is not an installed version. Missing, unsupported or stale lockfiles leave uncertainty. Never execute builds to resolve it. |
| Processes/listeners | Accessible process and socket metadata | Process permissions and command availability vary. A listener does not prove internet exposure; no visible listener does not prove isolation. |
| Containers | Accessible Docker metadata | An unavailable Docker socket is a gap. Metadata alone does not inventory all packages in an image or running filesystem. |
| Optional Syft | Already installed SBOM tool | Adds discovered package evidence; unsupported catalogers and inaccessible paths remain gaps. |
| Optional Trivy | Already installed host/container scanner | Distribution-aware results depend on its databases, supported targets, permissions and freshness. |

Use the result's actual collectors to describe coverage. Do not claim optional
tools ran because they are mentioned here. A tool's failure or timeout must
remain visible. A failed inventory must not silently replace the previous
usable map with an empty success.

## Advisory evidence

Source routing follows the inventory: ecosystem advisories, known-exploitation
context and relevant vendor/distribution/runtime routes. Read
[sources.md](sources.md) for supported adapters and primary references. OSV
records can lack a CVE number; they are still advisories. Withdrawn records
must not become active findings. Multiple fixed branches stay separate.

Do not confirm an affected-version match when the installed version is
unresolved. Distinguish direct affected evidence from a candidate requiring
verification. Prefer distro evidence for distro packages because vendors may
backport fixes without adopting an upstream version number.

Every check reports source success/failure and cache age. A response served from
cache does not become fresh merely because the report was regenerated. Stale or
missing sources prevent a complete clean result. `--fail-on none` controls the
finding threshold; it does not waive incomplete-check status.

## Priority wording

Combine severity, known exploitation, attack prerequisites and observed
component reachability. Keep raw severity visible when practical priority
differs. An internet-reachable network service with exploitation evidence
deserves prompt attention. A local attack remains relevant on multi-user hosts
or when an attacker can already execute code. User-interaction vulnerabilities
can matter without inbound ports.

Use concise statements such as “Network vulnerability; external reachability
unknown” or “Local privilege escalation; does not require an inbound port.”
AV:N also describes outbound-client vulnerabilities: inbound topology or
component bindings alone are not a reason to lower their priority. Restricted
inbound exposure reduces priority only with fresh finding-specific evidence that
exploitation needs an inbound-service path.
CGNAT, a private address and loopback binding are observations about routes;
none establishes the full threat model. Say what evidence is missing instead
of inventing a reachability conclusion.
