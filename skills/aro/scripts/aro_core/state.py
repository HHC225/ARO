"""Atomic local state and inventory reconciliation."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .common import digest, utc_now

_VOLATILE = {"scanned_at", "updated_at", "fetched_at", "checked_at", "last_seen_at", "last_observed_at",
             "pid", "pids", "process_id", "process_ids", "elapsed_seconds", "duration", "uptime",
             "fingerprint", "source_plan", "delta", "created_at", "captured_at", "processes"}


def _stable(value):
    if isinstance(value, dict):
        ignored = _VOLATILE | ({"detail"} if "collector" in value and "status" in value else set())
        return {key: _stable(item) for key, item in sorted(value.items()) if key not in ignored}
    if isinstance(value, list):
        items = [_stable(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return value


def inventory_fingerprint(inventory: dict) -> str:
    return digest(_stable(inventory))


def _uncertain(component: dict, coverage: list[dict]) -> bool:
    owner = component.get("collector") or component.get("metadata", {}).get("collector")
    path = str(component.get("path", ""))
    bad = [row for row in coverage if row.get("status") in {"error", "partial", "unavailable", "skipped"}]
    kind, source = component.get("kind"), component.get("source")
    owners = {owner}
    if kind == "os-package" or source in {"dpkg-query", "rpm", "apk", "pacman"}:
        owners.update({"os-packages", "host"})
    if kind in {"os", "operating-system", "runtime", "windows-application", "hotfix"}:
        owners.add("host")
    if source in {"windows-registry", "windows-hotfix", "windows-os"} or component.get("metadata", {}).get("windows_os"):
        owners.update({"windows", "host"})
    if source == "windows-registry":
        owners.add("windows-apps")
    if source == "windows-hotfix":
        owners.add("windows-hotfixes")
    if component.get("id") == "windows-os":
        owners.update({"windows", "windows-os", "host"})
    if source == "python-metadata" and component.get("metadata", {}).get("interpreter"):
        owners.add("host")
    if kind == "container-image" or component.get("metadata", {}).get("image_id"):
        owners.add("docker")
    for row in bad:
        collector = row.get("collector")
        if collector in owners:
            return True
        scope = row.get("scope") or row.get("path")
        if scope and path:
            try:
                if Path(path).is_relative_to(Path(str(scope))):
                    return True
            except (OSError, ValueError):
                pass
        if collector in {"roots", "discovery"} and path and not scope:
            return True
    # Unscoped collector errors can make disappearance ambiguous. An unavailable
    # optional deep scanner alone does not invalidate native package removal.
    return any(not row.get("scope") and not row.get("path") and not owner for row in bad)


def reconcile_inventory(previous: dict | None, current: dict) -> tuple[dict, dict]:
    merged = copy.deepcopy(current)
    old = {item["id"]: item for item in (previous or {}).get("components", [])}
    new = {item["id"]: item for item in merged.get("components", [])}
    delta = {"first_run": previous is None, "added": [], "removed": [], "changed": [],
             "missing_unverified": [], "unchanged_count": 0, "coverage_changed": False,
             "network_changed": False}
    for key, item in new.items():
        item.pop("evidence_status", None)
        if key not in old:
            delta["added"].append(copy.deepcopy(item))
        elif _stable(item) != _stable({k: v for k, v in old[key].items() if k != "evidence_status"}):
            delta["changed"].append({"id": key, "before": copy.deepcopy(old[key]), "after": copy.deepcopy(item)})
        else:
            delta["unchanged_count"] += 1
    for key in old.keys() - new.keys():
        if _uncertain(old[key], merged.get("coverage", [])):
            retained = copy.deepcopy(old[key])
            retained["evidence_status"] = "stale"
            new[key] = retained
            delta["missing_unverified"].append(copy.deepcopy(retained))
        else:
            delta["removed"].append(copy.deepcopy(old[key]))
    merged["components"] = sorted(new.values(), key=lambda row: row["id"])
    for field in ("added", "removed", "changed", "missing_unverified"):
        delta[field].sort(key=lambda row: row["id"])
    if previous:
        delta["coverage_changed"] = _stable(previous.get("coverage", [])) != _stable(current.get("coverage", []))
        delta["network_changed"] = _stable(previous.get("network", {})) != _stable(current.get("network", {}))
    merged["fingerprint"] = inventory_fingerprint(merged)
    delta["map_changed"] = previous is None or merged["fingerprint"] != inventory_fingerprint(previous)
    return merged, delta


class StateStore:
    def __init__(self, root: Path):
        supplied = Path(root).expanduser()
        if supplied.is_symlink():
            raise ValueError("The state directory must not be a symbolic link.")
        self.root = supplied.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def path(self, relative: str) -> Path:
        candidate = self.root / relative
        if Path(relative).is_absolute() or not candidate.resolve().is_relative_to(self.root):
            raise ValueError("State paths must remain inside the state directory.")
        return candidate

    def read(self, relative: str, default=None):
        path = self.path(relative)
        if not path.exists():
            return copy.deepcopy(default)
        if path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError(f"State file is too large: {relative}")
        try:
            with path.open(encoding="utf-8") as stream:
                return json.load(stream)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ValueError(f"Invalid state file {relative}; preserve it for inspection before retrying.") from exc

    def write(self, relative: str, value) -> Path:
        path = self.path(relative)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".aro-", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return path

    @contextmanager
    def lock(self):
        lock_path = self.path(".lock")
        try:
            fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise RuntimeError("Another ARO operation holds the state lock. If its process has exited, remove only the stale .lock file and retry.") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"pid": os.getpid(), "created_at": utc_now()}, stream)
            yield
        finally:
            lock_path.unlink(missing_ok=True)
