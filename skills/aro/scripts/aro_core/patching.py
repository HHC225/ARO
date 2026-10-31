"""Approval-bound patch plans with fixed adapters and post-change inventory."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

from .common import digest, parse_time, run_argv, utc_now
from .state import inventory_fingerprint


class PatchRefused(ValueError):
    """A patch cannot be proven to match the reviewed plan."""


def _file_hash(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise PatchRefused(f"Unsafe or oversized patch input: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tool(name: str, resolver) -> str:
    executable = resolver(name)
    if not executable or not Path(executable).is_absolute():
        raise PatchRefused(f"Required package manager is unavailable: {name}")
    return str(executable)


def _numeric_version(value: str):
    if re.fullmatch(r"v?\d+(?:\.\d+)*", value):
        return tuple(int(part) for part in value.lstrip("v").split("."))
    return None


def _newer(installed: str, target: str, manager: str, resolver, compare_runner) -> bool:
    # Distro version ordering belongs to the distro package manager.
    if manager == "apt":
        return compare_runner([_tool("dpkg", resolver), "--compare-versions", installed, "lt", target], timeout=15).get("returncode") == 0
    if manager == "apk":
        result = compare_runner([_tool("apk", resolver), "version", "-t", installed, target], timeout=15)
        return result.get("returncode") == 0 and result.get("stdout", "").strip() == "<"
    left, right = _numeric_version(installed), _numeric_version(target)
    if left is None or right is None:
        raise PatchRefused("This version scheme requires a native vendor update plan; automatic version ordering is unavailable.")
    length = max(len(left), len(right))
    return left + (0,) * (length - len(left)) < right + (0,) * (length - len(right))


def _manager(component: dict) -> str:
    manager = str(component.get("manager") or component.get("metadata", {}).get("manager") or "")
    return {"dpkg": "apt", "dpkg-query": "apt", "pip-metadata": "pip", "package-lock": "npm"}.get(manager, manager)


def _steps(component: dict, target: str, resolver) -> tuple[list[dict], list[dict], list[str]]:
    name = str(component.get("name") or "")
    metadata = component.get("metadata", {})
    manager = _manager(component)
    if metadata.get("selected") is False:
        raise PatchRefused("This installation has unverified or nonpublic package provenance; use a separately reviewed source-specific update.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_:@/-]*|@[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise PatchRefused("Package name is not valid for an automatic patch adapter.")
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+:~_-]*", target):
        raise PatchRefused("Target version must be an exact vendor version, not a command or range.")
    if component.get("evidence_status") == "stale":
        raise PatchRefused("Re-scan this component successfully before planning a patch.")
    files, warnings, cwd = [], [], None
    if manager == "apt":
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", name):
            raise PatchRefused("Invalid Debian binary package name.")
        architecture = metadata.get("architecture") or component.get("scope")
        if architecture:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", str(architecture)):
                raise PatchRefused("Invalid Debian architecture.")
            if ":" in name and name.rsplit(":", 1)[1] != architecture:
                raise PatchRefused("Debian package architecture evidence is inconsistent.")
            if ":" not in name:
                name += ":" + architecture
        argv = [_tool("apt-get", resolver), "install", "--assume-yes", "--only-upgrade", "--no-remove", "--", f"{name}={target}"]
        warnings = ["Requires an already authorized administrator session. Native dependency changes must be reviewed.",
                    "The distribution package may restart affected services during installation.",
                    "Package metadata must already be fresh; ARO does not run apt update automatically."]
    elif manager == "apk":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*", name):
            raise PatchRefused("Invalid APK package name.")
        argv = [_tool("apk", resolver), "add", "--upgrade", "--", f"{name}={target}"]
        warnings = ["Requires an administrator session; the native transaction may change dependencies and run package hooks."]
    elif manager == "pip":
        interpreter = metadata.get("interpreter") or metadata.get("python_executable")
        prefix = metadata.get("environment_prefix")
        if (not interpreter or os.path.normcase(os.path.abspath(interpreter)) != os.path.normcase(os.path.abspath(sys.executable))
            or not prefix or os.path.normcase(os.path.abspath(prefix)) != os.path.normcase(os.path.abspath(sys.prefix))):
            raise PatchRefused("Run ARO with the target environment's Python interpreter before patching this pip package.")
        location = component.get("path")
        if not location or not Path(location).resolve().is_relative_to(Path(sys.prefix).resolve()):
            raise PatchRefused("This distribution is outside the active Python environment; use a separately reviewed user/system environment update.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise PatchRefused("Invalid Python distribution name.")
        # Preserve a venv's executable path, and prevent a project-local pip.py
        # or PYTHONPATH entry from replacing the actual installer.
        argv = [os.path.abspath(sys.executable), "-I", "-m", "pip", "--isolated", "install", "--upgrade", "--no-user", "--prefix", os.path.abspath(sys.prefix), "--no-deps", "--only-binary=:all:", "--disable-pip-version-check", f"{name}=={target}"]
        warnings = ["Only this environment is changed. Dependencies and project lockfiles are not automatically upgraded.",
                    "Only prebuilt wheels are accepted; source-build hooks are not executed."]
    elif manager == "npm":
        if component.get("scope") != "node_modules/" + name:
            raise PatchRefused("Only the resolved top-level npm installation can be patched automatically; nested, alias and workspace installations require a parent-dependency plan.")
        project = metadata.get("project_path") or metadata.get("project")
        if not project:
            raise PatchRefused("A verified npm project path is required.")
        cwd = str(Path(str(project)).resolve())
        manifest = Path(cwd) / "package.json"
        if not manifest.is_file() or manifest.is_symlink():
            raise PatchRefused("The npm package manifest is missing or is a symbolic link.")
        _file_hash(manifest)
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise PatchRefused("Cannot read the npm project manifest.") from exc
        scopes = [key for key in ("dependencies", "devDependencies", "optionalDependencies") if name in data.get(key, {})]
        if len(scopes) != 1:
            raise PatchRefused("Only unambiguous direct npm dependencies can be patched automatically; update the parent dependency for transitive packages.")
        scope = {"dependencies": "--save-prod", "devDependencies": "--save-dev", "optionalDependencies": "--save-optional"}[scopes[0]]
        for filename in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
            path = Path(cwd) / filename
            if path.exists():
                files.append({"path": str(path), "sha256": _file_hash(path)})
        if len(files) < 2:
            raise PatchRefused("A resolved npm lockfile is required before automatic updates.")
        executable = _tool("npm", resolver)
        if os.name == "nt" and executable.lower().endswith((".cmd", ".bat")):
            # Use Node directly so package names never pass through cmd.exe.
            node = _tool("node", resolver)
            npm_cli = Path(executable).parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
            if not npm_cli.is_file():
                raise PatchRefused("Cannot locate npm-cli.js for shell-free Windows execution.")
            prefix = [node, str(npm_cli)]
        else:
            prefix = [executable]
        argv = prefix + ["install", "--global=false", "--prefix", cwd, "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", scope, "--", f"{name}@{target}"]
        warnings = ["The dependency resolver can change transitive packages and both manifest and lockfile.",
                    "Lifecycle scripts are disabled; applications requiring build hooks need a separate reviewed step."]
    elif manager == "winget":
        package_id = str(metadata.get("winget_id") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]+", package_id):
            raise PatchRefused("An exact installed WinGet package ID is required; display-name guesses are not allowed.")
        argv = [_tool("winget", resolver), "upgrade", "--id", package_id, "--exact", "--version", target, "--source", "winget", "--disable-interactivity"]
        warnings = ["The vendor installer may request elevation or restart services; ARO never authorizes a reboot.",
                    "An installer may decline an unattended update. Review its result before retrying."]
    else:
        raise PatchRefused(f"Manual update required for manager {manager or 'unknown'}; container images must be rebuilt and redeployed from a reviewed image/Dockerfile change.")
    return [{"argv": argv, "cwd": cwd, "timeout": 600}], files, warnings


def _native_preview(manager: str, steps: list[dict], runner) -> dict | None:
    if manager not in {"apt", "apk"}:
        return None
    argv = list(steps[0]["argv"])
    argv.insert(1, "--simulate")
    outcome = runner(argv, cwd=steps[0].get("cwd"), timeout=60)
    if outcome.get("truncated"):
        raise PatchRefused("The native update preview was truncated; use a separately reviewed complete transaction.")
    if outcome.get("returncode") != 0:
        raise PatchRefused("The native package manager could not simulate this exact update. Refresh vendor metadata separately or use a manual update plan.")
    output = outcome.get("stdout", "") + "\n" + outcome.get("stderr", "")
    if manager == "apt":
        changes = [line.strip() for line in output.splitlines() if line.startswith(("Inst ", "Remv ", "Conf "))]
    else:
        changes = [line.strip() for line in output.splitlines() if any(word in line for word in ("Upgrading ", "Installing ", "Purging ", "Downgrading "))]
    if not changes:
        raise PatchRefused("The native package manager did not report a reviewable update transaction.")
    if any(line.startswith("Remv ") or "Purging " in line or "Downgrading " in line for line in changes):
        raise PatchRefused("This update would remove or downgrade packages; a separate manual plan is required.")
    return {"argv": argv, "changes": changes}


def create_plan(inventory: dict, finding: dict, target_version: str, *, resolver=shutil.which, compare_runner=run_argv, preview_runner=run_argv) -> dict:
    component = next((row for row in inventory.get("components", []) if row["id"] == finding.get("component_id")), None)
    if component is None:
        raise PatchRefused("The finding's component is absent from the current map.")
    if finding.get("match_confidence") not in {"confirmed", "exact", "high", "vendor", "version", "exact_version", "affected", "vendor-source-package", "vendor-package", "vendor_applicability"}:
        raise PatchRefused("Automatic patching requires a confirmed version match.")
    if target_version not in finding.get("fixed_versions", []):
        raise PatchRefused("The target must be an exact fixed version listed by the selected advisory.")
    steps, files, warnings = _steps(component, target_version, resolver)
    if not _newer(str(component.get("version") or ""), target_version, _manager(component), resolver, compare_runner):
        raise PatchRefused("The proposed fixed version is not newer than the installed version. Choose the correct fixed branch.")
    native_preview = _native_preview(_manager(component), steps, preview_runner)
    now = dt.datetime.now(dt.timezone.utc)
    plan = {"schema_version": 1, "created_at": now.isoformat(), "expires_at": (now + dt.timedelta(minutes=30)).isoformat(),
            "inventory_fingerprint": inventory_fingerprint(inventory), "component_id": component["id"],
            "component_name": component["name"], "installed_version": component["version"], "target_version": target_version,
            "manager": _manager(component), "finding_id": finding.get("finding_id"),
            "advisory_id": finding.get("id"), "source_url": finding.get("source_url"),
            "steps": steps, "input_files": files, "warnings": warnings, "native_preview": native_preview,
            "restart_policy": "No ARO-triggered restart or reboot; package/vendor hooks may restart services.",
            "rollback": {"original_version": component["version"], "files_to_backup": [item["path"] for item in files],
                         "note": "Use the recorded package version and backed-up lockfiles for a separately approved rollback. Database and application state require an operator backup."}}
    plan["plan_hash"] = digest(plan)
    return plan


def apply_plan(plan: dict, approval: str | None, inventory: dict, *, runner=run_argv, rescan=None,
               resolver=shutil.which, backup_dir: Path | None = None, journal=None, preview_runner=run_argv) -> dict:
    expected = digest({key: value for key, value in plan.items() if key != "plan_hash"})
    if not approval or approval != plan.get("plan_hash") or expected != approval:
        raise PatchRefused("Explicit approval must match the unchanged plan's full SHA-256 hash.")
    expires = parse_time(plan.get("expires_at"))
    if expires is None or expires <= dt.datetime.now(dt.timezone.utc):
        raise PatchRefused("The patch plan has expired; create and review a new plan.")
    if inventory_fingerprint(inventory) != plan.get("inventory_fingerprint"):
        raise PatchRefused("The software map changed after planning; create and review a new plan.")
    component = next((row for row in inventory.get("components", []) if row["id"] == plan.get("component_id")), None)
    if component is None:
        raise PatchRefused("The patch target no longer exists.")
    steps, files, _ = _steps(component, plan["target_version"], resolver)
    if steps != plan.get("steps") or files != plan.get("input_files") or _manager(component) != plan.get("manager"):
        raise PatchRefused("Patch commands, executables, or input files no longer match the allowed adapter.")
    if rescan is None:
        raise PatchRefused("A post-patch inventory callback is required.")
    if _native_preview(_manager(component), steps, preview_runner) != plan.get("native_preview"):
        raise PatchRefused("The native dependency transaction changed after approval. Create and review a new plan.")
    backups = []
    if files:
        if backup_dir is None:
            raise PatchRefused("A local backup directory is required for manifest changes.")
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        for index, item in enumerate(files):
            source = Path(item["path"])
            destination = backup_dir / f"{index}-{source.name}"
            with destination.open("xb") as stream:
                stream.write(source.read_bytes())
            if os.name != "nt":
                destination.chmod(0o600)
            backups.append({"original": str(source), "backup": str(destination), "sha256": item["sha256"]})
    result = {"schema_version": 1, "plan_hash": approval, "started_at": utc_now(), "status": "running", "steps": [], "backups": backups}
    if journal:
        journal(result)
    try:
        for step in steps:
            outcome = runner(step["argv"], cwd=step.get("cwd"), timeout=step["timeout"])
            result["steps"].append({"argv": step["argv"], **outcome})
            if journal:
                journal(result)
            if outcome.get("returncode") != 0:
                result["status"] = "failed"
                break
        else:
            result["status"] = "executed"
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = f"Patch execution interrupted: {type(exc).__name__}"
    finally:
        try:
            fresh = rescan()
            result["inventory"] = fresh
            actual = next((row for row in fresh.get("components", []) if row["id"] == component["id"]), None)
            result["observed_version"] = actual.get("version") if actual else None
            if result["status"] == "executed":
                result["status"] = "applied" if actual and actual.get("version") == plan["target_version"] and actual.get("evidence_status") != "stale" else "verification_failed"
        except Exception as exc:
            result["status"] = "verification_failed"
            result["rescan_error"] = f"Post-patch scan failed: {type(exc).__name__}"
        result["finished_at"] = utc_now()
        result["service_health"] = "unverified; run the application's health checks before declaring recovery"
        if journal:
            journal(result)
    return result
