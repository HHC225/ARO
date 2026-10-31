# Operational workflow

Run these commands from the installed `aro` skill directory, or replace
`scripts/aro.py` with its absolute path. Use Python 3.11+; Windows can use
`python` or `py -3`. The scanner writes ARO state while leaving installed
software and project files unchanged during a check.

## Inventory and check

```bash
python3 scripts/aro.py scan --root /srv/my-app --format json
python3 scripts/aro.py check --root /srv/my-app --root /opt/another-app --format json
python3 scripts/aro.py sources --format json
python3 scripts/aro.py check --offline --format json
python3 scripts/aro.py check --refresh --format json
python3 scripts/aro.py config --show --format json
```

`scan` and `init` are map-only. `check` refreshes inventory and queries the
sources relevant to discovered software. A previous map is comparison evidence,
not permission to skip a new scan. Explicit roots persist into configuration.
Without saved roots the scanner considers the current directory and bounded
common application locations: existing `/opt`, `/srv`, `/var/www`, `/app`,
`/workspace` and user home on Linux; current directory/user home plus discovered
process/service paths on Windows. Use explicit roots for predictable project
coverage. File/depth/time bounds and permissions can limit discovery.

## State and configuration

Default state directories:

- Linux: `${XDG_STATE_HOME:-~/.local/state}/aro`.
- Windows: `%LOCALAPPDATA%/ARO`, with `~/AppData/Local/ARO` as fallback.

Append `--state-dir PATH` to select an isolated state directory, especially for
tests or different hosts. Do not place production state inside the installed
skill or commit it to a repository. State contains software details and paths.

`config.json` is created automatically. Inspect it with `config --show`; edit
that JSON to configure roots, package-name exclusions, cache age and scan
bounds. Preserve other keys and valid JSON. Example values:

```json
{
  "roots": ["/srv/my-app"],
  "exclude_packages": ["@private/*", "internal-*"],
  "cache_ttl_hours": 6,
  "max_cache_age_hours": 168,
  "scan": {"max_files": 100000, "max_depth": 12, "command_timeout": 20}
}
```

The state also contains `inventory.json`, `report.json`, cached advisory
responses under `cache/`, immutable plans under `plans/` and patch journals
under `history/`. A lock prevents simultaneous writers. Atomic files preserve
the last usable map if collection fails. Do not delete state to work around a
lock held by a running process. After a crash, follow the CLI's error rather
than assuming the last report represents the current host.

## Exposure evidence

Record only facts confirmed by the user or direct evidence:

```bash
python3 scripts/aro.py exposure --cgnat confirmed --public-ipv4 no --public-ipv6 no --inbound-forwarding no --tunnels no
python3 scripts/aro.py exposure --component COMPONENT_ID --reachability internet --evidence "User confirmed the reverse proxy routes this service publicly"
python3 scripts/aro.py exposure --finding FINDING_ID --attack-path inbound-service --evidence "Vendor advisory confirms exploitation requires an inbound request to this service"
```

Component-specific reachability and finding-specific attack-path evidence expire
after seven days by default. Attack-path choices are `inbound-service`,
`outbound-client`, `local` and `unknown`. A fresh CGNAT boundary requires all five
flags in the first command together; partial topology edits invalidate it.
Topology restricts inbound access only. A priority reduction also requires fresh
finding-specific `inbound-service` evidence; AV:N or a component binding alone
does not mitigate outbound-client CVEs.
Host-level observations do not assign reachability to every component and
should be refreshed when the network changes. CGNAT concerns one IPv4 route: it does not rule
out IPv6, tunnels, reverse proxies, forwarded ports, LAN access, malicious
documents or local privilege escalation. Listener binding is useful evidence,
but external routing and firewall policy may remain unknown.

## Network and privacy

No agent-side web browsing is needed. The Python process still needs outbound
HTTPS to advisory endpoints unless an appropriate cache is available. Offline
mode makes no advisory requests and identifies missing/stale data. Package
names and installed versions sent to advisory services can reveal internal
technology choices; exclude sensitive names before the first online check.
The scanner does not upload application source or credentials. Keep reports,
maps and diagnostic logs private unless deliberately redacted for sharing.
