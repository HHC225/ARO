# ARO

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

ARO is an agent skill for developers who run Linux or Windows servers and want
to know which installed software needs security attention. It refreshes a local
software map, checks relevant advisory sources, explains practical risk in short
lines, and prepares a bounded update plan for your approval.

Python **3.11 or newer** is required. The core uses only Python's standard
library. Bash and PowerShell launchers are included. ARO does not install its
prerequisites or optional scanners automatically.

## Install

With Node.js/npm available, use the [Skills CLI](https://github.com/vercel-labs/skills/blob/main/docs/commands.md):

```bash
npx skills add HHC225/ARO --skill aro
```

Choose your agent and installation scope in the installer. An agent that can
read `SKILL.md` and execute local Python can also use a manual installation:

```bash
git clone https://github.com/HHC225/ARO.git
mkdir -p .agents/skills
cp -R ARO/skills/aro .agents/skills/aro
```

Run this from your project directory. Depending on your client, replace
`.agents/skills` with `.claude/skills` or `.codex/skills`. Copy the **whole**
`skills/aro` folder, including scripts and references. The repository itself can
also be used directly without copying. On Windows PowerShell:

```powershell
git clone https://github.com/HHC225/ARO.git
New-Item -ItemType Directory -Force .agents/skills | Out-Null
Copy-Item -Recurse ARO/skills/aro .agents/skills/aro
```

The installation command downloads third-party code; review it before use.
The Skills installer has its own behavior and telemetry settings, separate
from ARO's scanner. No ChatGPT-specific installation is required.

## Use with an agent

Ask: **“Use $aro to check this server and my app, explain the risks briefly,
and prepare any updates for my approval.”** The skill instructions are English;
the agent can explain results in your language.

The first check creates a persistent software map. Later checks inventory the
host again and record new, removed and changed software. A typical finding is
one line: **component · current → fixed · practical risk and reason · source
link**. ARO preserves unresolved versions, unknown exposure and source failures
as visible limitations. Known nonpublic npm/Cargo/Python origins stay in the local map as unselected evidence and are not queried.

## Run directly

Use `check --refresh` to request current advisory data even when a fresh cache exists; it cannot be combined with `--offline`.

From this repository:

```bash
python3 skills/aro/scripts/aro.py check --root /srv/my-app
python3 skills/aro/scripts/aro.py check --root /srv/my-app --format json
bash skills/aro/scripts/aro.sh check --root /srv/my-app
```

On Windows, use Python 3.11+ as `python` or `py -3` when necessary:

```powershell
python skills/aro/scripts/aro.py check --root C:/apps/my-app
powershell -File skills/aro/scripts/aro.ps1 check --root C:/apps/my-app
```

After copying the skill, replace the path above with its installed location.

| Command | Purpose |
| --- | --- |
| `init` or `scan` | Refresh only the local software map |
| `check` | Refresh inventory and check relevant advisories |
| `sources` | Show the advisory routes selected for the inventory |
| `config --show` | Show effective configuration |
| `exposure` | Record confirmed network facts or component reachability |
| `plan --finding ID --target-version VERSION` | Save an exact bounded update plan |
| `apply --plan PATH --approve HASH` | Execute that approved plan after preflight checks |

Use repeatable `--root PATH` to select application directories; supplied roots
persist. Without saved roots, discovery uses the current directory and common
platform application locations under bounded file/depth/time limits. Give
explicit roots when you need predictable project coverage. `--state-dir PATH`
selects another state directory. `check --offline` uses available cached data
without advisory requests. `--format json` exposes detailed machine-readable
results.

`check --fail-on high`, `critical`, `any` or `none` controls the findings
threshold; the default is `none`. Exit codes are `0` for a completed operation
under threshold, `1` for threshold findings, `2` for an error/incomplete check,
and `3` for patch approval/stale-plan refusal. Incomplete status takes precedence
over a findings threshold. Inspect coverage even when no findings are returned.

## What is checked

ARO collects accessible OS/package-manager metadata, runtimes, processes,
listeners, supported project manifests/lockfiles and Docker metadata. Already
installed **Syft** and **Trivy** can add supported SBOM and distribution-aware
host/container coverage. Missing tools, permission failures, scan bounds and
unresolved versions appear in coverage; ARO does not claim to discover every
custom binary or every container package.

Advisory routes are selected from discovered software: ecosystem advisories,
known-exploitation context and applicable vendor/distribution/runtime evidence.
See [source coverage](skills/aro/references/sources.md) and the result of
`sources` for exact adapters. Distribution backports must be evaluated using
distribution evidence rather than upstream version comparisons. An advisory
without a CVE identifier can still be relevant.

Implemented coverage on both platforms is bounded by available metadata and tools:

| Area | Platform and supported evidence | Advisory route / limits |
| --- | --- | --- |
| Linux OS | dpkg, RPM or apk package metadata | Mapped Debian/Ubuntu releases: direct OSV using native source package/version, including backports. Other distributions: optional Trivy; unsupported releases remain gaps. |
| Windows OS | OS/build, installed software and update metadata | Read-only Windows Update Agent search for applicable missing security updates. Configured update service/policy limits coverage; OS update installation is manual. |
| Python projects | Linux/Windows: pinned `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, installed distribution metadata | OSV PyPI. Unresolved manifest ranges are gaps. |
| JavaScript projects | Linux/Windows: `package-lock.json`, `npm-shrinkwrap.json` | OSV npm. No native Yarn/pnpm lockfile parser. |
| Other project locks | Linux/Windows: `Cargo.lock`, `go.mod`/`go.sum`, `composer.lock`, `Gemfile.lock`, `packages.lock.json`/`project.assets.json`, exact `gradle.lockfile` coordinates | OSV crates.io, Go, Packagist, RubyGems, NuGet, Maven. Maven/Gradle manifests without resolved locks are gaps; no full Maven resolver. `go.sum` alone does not prove a selected dependency. |
| Runtimes | Accessible Python, Node.js, Go and other detected versions | Official CPython/Node/Go records; PHP/Ruby/.NET/Rust repository feeds are partial. JDK vendor matching is unsupported; distro builds need backport review. |
| Containers / SBOM | Accessible Docker metadata; already installed Syft/Trivy | Optional deeper inventory and local immutable-image OS findings. Requires local daemon access and usable scanner databases; no guarantee of complete image coverage. |

CISA KEV adds known-exploitation context by exact CVE identity; absence from KEV does not establish absence of exploitation. Windows WUA search never downloads or installs updates and is not a complete MSRC CVE applicability engine.

**CGNAT is not proof of safety.** IPv6, tunnels, reverse proxies, forwarded ports,
LAN access, local privilege escalation and user interaction can still matter.
ARO reports unknown exposure explicitly. Host observations do not automatically
set every component's reachability. Inbound restrictions alone do not lower outbound-client risk; priority reduction needs fresh finding-specific inbound-service evidence. Record only confirmed facts, for example:

```bash
python3 skills/aro/scripts/aro.py exposure --cgnat confirmed --public-ipv4 no --public-ipv6 no --inbound-forwarding no --tunnels no
```

## Updates require a concrete approval

Create a plan from a current finding and an exact target version:

```bash
python3 skills/aro/scripts/aro.py plan --finding FINDING_ID --target-version VERSION
python3 skills/aro/scripts/aro.py apply --plan /path/to/plan.json --approve FULL_PLAN_HASH
```

Review the actual plan before running `apply`: exact arguments, target,
dependency effects, working directory, inventory hash, expiry and rollback
limits. Approval covers that artifact and scope. Changed software, an expired
plan or a modified plan requires a new plan and approval. Support is limited
to apt/apk, pip in ARO's own interpreter/prefix (outside-prefix packages refused), unambiguous top-level direct npm
dependencies with a manifest/lockfile (nested/alias/workspace installs refused), and verified exact WinGet IDs. apt/apk simulate the dependency transaction and recheck it before execution. pip uses
prebuilt wheels without dependency updates; npm disables lifecycle scripts but
may change transitive packages and lockfiles. dnf/RPM, generic Windows OS
updates, containers and unsupported targets receive manual guidance. Plans
expire after 30 minutes. A fixed version listed by an advisory may be unavailable
or incompatible with your app; only supported version schemes can be ordered
automatically.

ARO journals execution and inventories again after success or partial failure.
ARO does not automatically elevate privileges or trigger a separate service
restart or reboot. Native package/vendor hooks **may restart services**, so
approval must cover dependencies and downtime. Service health remains
unverified until the application's authorized health checks run. A package
manager's successful exit alone is not proof that remediation is complete.

## State, network access and privacy

State lives outside the installed skill and checked repositories:

- Linux: `${XDG_STATE_HOME:-~/.local/state}/aro`.
- Windows: `%LOCALAPPDATA%/ARO` (fallback `~/AppData/Local/ARO`).

The automatically created `config.json` supports roots, `exclude_packages`
package-name globs, network observations, cache age and scan bounds. Inspect it
with `config --show`; edit valid JSON for other changes. See
[workflow](skills/aro/references/workflow.md) for an example. State includes the
current inventory/report, advisory cache, immutable plans and patch journals.
Keep it private and out of Git.

Checks read local metadata and do not modify installed software or app files.
Advisory requests can disclose **package names and versions** to the configured
services; they do not upload application source or credentials. Exclude private
package names before an online check if that disclosure is unacceptable.
Reports may contain local paths and software details.

No agent-side browser is required, but the scripts still need internet access
or a usable cache. Offline, stale and failed-source results retain their age
and coverage gaps. “No confirmed matches” describes checked coverage, not a
guarantee that the host is secure. External router/firewall policy, unsupported
software and inaccessible locations can remain unknown.

## Development and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for validation and contribution guidance,
[SECURITY.md](SECURITY.md) for reporting security issues, and
[LICENSE](LICENSE) for the MIT license. This repository contains the distributable
skill under [`skills/aro`](skills/aro); installing it does not require installing
this repository as a Python package.
