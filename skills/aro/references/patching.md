# Approval-bound patching

Patching is a separate operation from checking. Read the latest report and
select a current finding with an exact target version supported by the
applicable package manager. A listed fixed version can be unavailable in the
configured repository or incompatible with the project.

```bash
python3 scripts/aro.py plan --finding FINDING_ID --target-version VERSION
```

The plan is an immutable JSON artifact containing an inventory snapshot hash,
expiry, the exact command arguments and working directory, expected target and
plan hash. Review the actual artifact before requesting approval. Explain the
component, current → target version, which files/packages may change,
dependency resolution, privilege requirements, downtime/restart needs and
rollback limitations. An installer's own dependency resolution may change
more than one package; approval must cover that scope. Do not promise a
transactional rollback.

Supported adapters are deliberately bounded:

| Adapter | Conditions and effects |
| --- | --- |
| apt | Exact installed Debian-family binary package and distro version; simulates the native transaction and rechecks it at apply. Dependency resolution and package hooks apply. Package metadata must already be current: ARO does not run `apt update`. |
| apk | Exact installed Alpine package/version; simulates and rechecks the native transaction. Dependency resolution and hooks apply. |
| pip | Run ARO using the target environment's own Python interpreter and prefix; inherited/user-scope packages outside that prefix are refused. Uses isolated Python/pip, explicit prefix and prebuilt wheels with `--no-deps`; dependencies and project lockfiles are not updated. |
| npm | Unambiguous top-level direct dependency with a verified `package.json` and resolved lockfile. Nested, aliased and workspace installs are refused. Explicit non-global/project prefix; manifest, lockfile and transitive dependencies can change. Lifecycle scripts are disabled. |
| WinGet | Verified installed `winget_id`, exact ID and version; no display-name guessing. Vendor installers may refuse unattended updates or request elevation. |

Use only adapters actually accepted by `plan`. dnf/RPM, generic Windows OS
updates, container images, transitive npm dependencies, unresolved installations,
unavailable exact versions and ambiguous runtime mappings require manual
instructions. Container images need a reviewed rebuild and redeployment. Only
exact fixed versions listed in the chosen confirmed advisory are eligible.
For non-distro adapters, automatic ordering accepts simple numeric versions;
other version schemes require a manual/vendor plan. No adapter authorizes
installing a new scanner or changing an unrelated component. Plans expire after
30 minutes.

## Apply the exact artifact

After the user explicitly approves the displayed hash and scope:

```bash
python3 scripts/aro.py apply --plan /absolute/path/to/plan.json --approve PLAN_HASH
```

Use the full printed SHA. Approval of “fix vulnerabilities” without a concrete
plan is not approval of every future generated command. Existing explicit
authorization can cover the artifact when it identifies its exact scope.

Apply checks integrity, expiry and the current inventory before mutation. A
different inventory, changed plan, missing approval or invalid target is a
refusal: regenerate from a fresh check, review and obtain approval for the new
hash. Never bypass refusal by editing JSON, guessing hashes or running the
rejected command yourself.

Commands use validated arguments and an allowlist rather than advisory-provided
shell snippets. ARO does not automatically elevate privileges or trigger a
separate restart/reboot. Native package and vendor hooks may restart services;
approval must cover their downtime. If the package manager requires privilege
or user action, report it. If a dependency change or restart exceeds approved
scope, stop and present the added scope for approval.

## After success or failure

Apply journals its result and refreshes local inventory afterward, including
after partial failure. Read the resulting map, report and journal. Confirm the
installed version and advisory result rather than equating process exit zero
with a fixed vulnerability. Service health remains unverified: run only the
application health checks authorized by the user before declaring recovery.
If refresh fails, tell the user the patch outcome
is not fully verified and run a fresh `check` when the blocker is resolved.
Partial execution may leave changed software; report the recorded commands
and outcome and prepare a new plan for remaining work.

Manual instructions should use the official package/vendor documentation,
name the exact component and branch, and describe a check the user can run
afterward. Do not execute those instructions through an unsupported adapter or
silently restart applications to activate a fix.
