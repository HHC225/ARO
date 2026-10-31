# Advisory sources, matching, and freshness

ARO selects sources from the local software map. Its core uses Python 3.11+ standard-library HTTPS and needs no API key. An empty findings list is meaningful only alongside the source and inventory coverage states. `error`, `unavailable`, `stale`, and `partial` are not a clean check.

## Package dependencies: OSV

ARO submits exact ecosystem, package name, and installed/resolved version coordinates to `https://api.osv.dev/v1/querybatch`. It sends no project files, source code, credentials, machine hostname, or local path. It neither supplies a recent-publication cutoff nor queries unrelated ecosystems. Historical `go.sum` checksum entries marked `selected: false` are not installed-dependency evidence and are skipped. Coordinates with unverified private/custom-registry or local/git provenance also use `selected: false` and are excluded from public ecosystem requests; their local provenance reason remains available in inventory.

The batch API returns identifiers and modification timestamps, so ARO fetches each full record from `/v1/vulns/{id}`. It follows each query's individual `next_page_token`, including pages with no vulnerability entries, with bounded pages, record count, requests, bytes, timeouts, and retries. A repeated token, truncated pagination, invalid shape, wrong package identity, missing affected evidence, or failed full-record fetch makes coverage incomplete. Withdrawn records are excluded. Multiple fixed branches remain separate, in source order; ARO does not choose a version by string sorting.

The mapped application ecosystems are PyPI, npm, Go, crates.io, Packagist, RubyGems, NuGet, Maven, Hex, Pub, Hackage, SwiftURL, ConanCenter, CRAN, GHC, and Julia. Inventory discovery support is narrower than that list. An arbitrary ecosystem string is never passed through as though its semantics were supported. For non-SemVer ecosystems the OSV exact version query supplies the ecosystem-specific version interpretation. Final numeric SemVer ranges and explicit affected-version lists receive additional local evidence checks. Unsupported prerelease/range syntax is never reinterpreted as a numeric final release.

Primary specifications:

- [OSV querybatch API and per-query pagination](https://google.github.io/osv.dev/post-v1-querybatch/)
- [OSV query API, including version matching behavior](https://google.github.io/osv.dev/post-v1-query/)
- [OSV full-record API](https://google.github.io/osv.dev/get-v1-vulns/)
- [OSV schema: affected packages, versions, range events, fixed branches, and withdrawal](https://ossf.github.io/osv-schema/)

## Debian and Ubuntu operating-system packages

Native dpkg inventory retains the binary package/version and its actual source package/version. ARO queries release-qualified `Debian:12` or `Ubuntu:24.04:LTS` coordinates using that source package/version; it does not assume a binary package has the same name or version as its source package. Debian point releases map to their Debian major release. Ubuntu LTS mapping requires observed release metadata. Packages with an installed `esm` source version use the corresponding `Ubuntu:Pro:YY.MM:LTS` namespace. Unknown releases or missing source mappings remain gaps and can be covered by the optional Trivy adapter.

OSV's distro ecosystem interpretation preserves epochs, revisions, tildes, and vendor backports. ARO never treats these source versions as upstream semantic versions. Findings retain source coordinate evidence under `source_package`; where Ubuntu records provide the affected binary's fixed version, it is kept separately from `source_fixed_versions`. Otherwise fixes remain source-package versions and need package-manager review. Ubuntu Pro entitlement, FIPS, realtime kernels, Livepatch applicability, third-party repositories, and end-of-support channels are not inferred from a normal version banner. A source-qualified match does not assert that a particular subscription update is installable.

Primary specifications:

- [Ubuntu Security Team OSV data, release/Pro namespaces, source packages, binary mappings, and ecosystem version ranges](https://documentation.ubuntu.com/security/security-updates/osv/)
- [OSV defined ecosystems, including Debian source-package and release semantics](https://ossf.github.io/osv-schema/#affectedpackage-field)
- [Debian version comparison policy](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version)

## Official runtime records

Runtime checks are separate from similarly named packages in public language registries. The runtime's observed version must be resolved; unknown versions are coverage gaps. Upstream runtime findings require vendor/backport review for distributor-customized builds. A trusted local dpkg ownership query (or explicit distro ownership metadata) identifies system runtimes where possible. Such upstream findings have `match_confidence: upstream-version`, an applicability note, and partial coverage; vendor source-package findings provide the stronger installed-package evidence.

| Runtime | Machine-readable source and matching | Limits |
| --- | --- | --- |
| CPython | Official `psf/advisory-database` full repository snapshot, then each PSF record's OSV import. OSV expands CPython Git affected ranges to release tags; a final installed release is matched to an explicitly affected tag for `https://github.com/python/cpython`. Official `python/cpython` published GitHub repository advisories supplement it. | Commit hashes are never represented as fixed release numbers. An import without release-tag evidence, an older-than-official import, or a failed import makes the source partial. Official withdrawals override older imports. Import lag and distributor backports remain limitations. |
| Node.js | Official `nodejs/security-wg` full snapshot, parsing individual `vuln/core/*.json` files. ARO evaluates declared vulnerable and patched ranges numerically, supports common final-release comparator/wildcard/caret/tilde unions, and retains branch-specific patched releases. Official `nodejs/node` public repository advisories supplement it. | `vuln/core/index.json` is deliberately not used as the sole inventory of records. Unknown range syntax, missing evidence, custom builds, and unsupported prereleases remain explicit gaps. |
| Go | Exact OSV `Go` queries for both `stdlib` and `toolchain`, with the installed Go version normalized from the `go` prefix. The Go team's imported OSV records cover both categories. | Package presence is not a proof that vulnerable symbols are reached; OS/architecture/build constraints and call reachability still require review. |
| PHP, Ruby, .NET, Rust | Published public repository advisories from `php/php-src`, `ruby/ruby`, `dotnet/runtime`, and `rust-lang/rust`. ARO requires a mapped runtime package identity and a supported explicit vulnerable-version range. All pages are visited up to the configured bound, without a recent-publication cutoff. | These feeds alone do not assure complete historical vendor coverage; each is marked partial. Library advisories such as a .NET NuGet package are not automatically attached to the entire runtime. |
| Other runtimes | No inferred mapping. | Explicitly unsupported. For example Java/JDK vendor update advisories require a vendor/product adapter. |

Repository snapshots are read in memory with compressed/decompressed and per-record size limits. Files are never extracted, imported, or executed. GitHub requests are public and unauthenticated; rate limiting or API refusal becomes a source error.

Primary sources:

- [Python Software Foundation advisory database](https://github.com/psf/advisory-database)
- [Example OSV PSF import showing Git ranges and expanded release tags](https://api.osv.dev/v1/vulns/PSF-2024-1)
- [Node.js Security WG database schema](https://github.com/nodejs/security-wg/blob/main/processes/vuln_db.md)
- [Go vulnerability database API and `stdlib`/`toolchain` schema](https://go.dev/doc/security/vuln/database)
- [Public GitHub repository advisory API, permissions, affected ranges, and pagination](https://docs.github.com/en/rest/security-advisories/repository-advisories)

## Other Linux distributions and local images: optional Trivy

For distributions without a native mapped source-coordinate route, ARO uses an already installed, trusted-system-directory Trivy executable. It does not install a scanner. A rootfs scan targets the local host root on Linux. Image scans accept only immutable local image IDs already in the inventory and force `--image-src docker`; arbitrary target references and remote target image pulls are not allowed. The number of local targets is bounded. Image packages must have the same inventory image identity; host packages with the same name are not substitutes.

Trivy runs with OS-package vulnerability scanning, dependency API lookups disabled (`--offline-scan`), telemetry disabled, a temporary working directory, and `TRIVY_*` environment overrides removed. Online checks may refresh the official `ghcr.io/aquasecurity/trivy-db:2` database; offline checks or explicit `trivy_skip_db_update` skip vulnerability DB updates. Java/check/VEX updates are disabled for this OS-only adapter. ARO never starts a daemon, installs an update, restarts a service, or pulls the target image during a check.

Findings are accepted only when the report's package name, installed version, local host/image scope, and known distribution identity match the map. Vendor fixed versions are preserved. Unmatched records are coverage gaps. Trivy DB `UpdatedAt` metadata is inspected; unknown DB age is partial, and an old DB is stale. Missing tools, permissions, unsupported CLI flags, absent local DBs in offline mode, and scan failures remain visible. Trivy itself may skip third-party packages or unsupported distributions; its successful execution is not proof of complete host coverage.

Primary documentation:

- [Trivy OS package/vendor advisory selection and distribution backports](https://trivy.dev/docs/dev/guide/scanner/vulnerability/)
- [Trivy rootfs CLI](https://trivy.dev/docs/latest/guide/references/configuration/cli/trivy_rootfs/)
- [Trivy image CLI, including `--image-src` and offline options](https://trivy.dev/docs/latest/guide/references/configuration/cli/trivy_image/)
- [Trivy database management and update flags](https://github.com/aquasecurity/trivy/blob/main/docs/guide/configuration/db.md)

## Windows operating-system coverage

A raw Windows product/build string is not enough to establish MSRC advisory applicability. The coordinator's Windows Update Agent adapter, when available, performs a read-only applicable security-update search; its findings and failures must remain visible. ARO does not claim that a WUA update listing is a complete MSRC product/CVE match, nor that an installed KB inventory alone proves all applicable security fixes are installed. Where WUA is absent, denied, offline without useful scan data, or otherwise unsupported, OS coverage is unavailable or partial. Language-package and upstream runtime queries still operate independently.

- [Windows Update Agent search interface](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide)

## Known exploitation: CISA KEV

ARO joins exact CVE identifiers in advisory IDs/aliases against the CISA Known Exploited Vulnerabilities catalog. A positive match sets `known_exploited` and retains catalog context; a missing match is not proof that exploitation never occurs. OSV advisories without CVEs are still findings. When no CVE finding needs enrichment, the source reports `not_applicable`, which is a completed check with no required KEV request. If the canonical CISA JSON feed fails, ARO can use the official `cisagov/kev-data` mirror, while retaining the primary failure in coverage. It does not use an unofficial KEV mirror.

- [Canonical CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Canonical JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [Official CISA mirror and synchronization description](https://github.com/cisagov/kev-data)

## Cache, privacy, deterministic output, and tests

Successful raw responses are cached locally by a hash of method, URL, and coordinate payload. Entries carry fetch time and use atomic replacement. The default freshness TTL is six hours; the default maximum stale/offline reuse age is seven days. Offline mode never performs HTTP requests. `force_refresh` bypasses a fresh cache during online checks so `check --refresh` can retrieve current source responses; combining it with offline mode still uses available cache and its original freshness. Fresh cached responses report their original fetch timestamp. Reused older entries and online-failure fallbacks report stale; expired, missing, corrupt, failed, or unwritable caches remain coverage issues. A cache write failure does not discard valid live findings.

Options include `force_refresh`, `offline`, `cache_ttl_hours`, `max_cache_age_hours`, `exclude_packages`, `timeout`, `retries`, `max_pages`, `max_advisories`, `max_runtime_records`, `max_requests`, `max_response_bytes`, and Trivy target/cache/age limits. Limits have hard upper bounds. `exclude_packages` uses case-sensitive globs against package names, `ecosystem:name`, and distro source package names before any corresponding package request. Configure exclusions for private coordinates. Unsupported local file/path dependency coordinates are not sent. Host metadata and paths remain local.

The built-in HTTP transport permits only fixed HTTPS advisory hosts and paths, refuses redirects, has bounded timeouts/retries/response sizes, and sends a fixed user-agent without credentials. An injected `requester(method, url, payload=None, timeout=seconds)` returns parsed JSON for API responses or archive bytes for the fixed official snapshots. Sorting of source plans, components, findings, and coverage is deterministic; source-provided fixed branches remain in their original order. No advisory text is executed or interpolated into a shell.

The advisory tests use explicit source payloads at the transport boundary. They cover multiple installed versions/ecosystems, historical pagination, full-record failures, withdrawals, fixed branches, runtime version evidence, numeric boundaries, source identity, distro backports and image scope, private exclusions, stale/expired/corrupt caches, source failures, and local-only scanner arguments. Live endpoint samples do not constitute a Windows or actual Trivy execution test.
