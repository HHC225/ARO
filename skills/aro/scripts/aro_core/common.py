"""Small shared primitives; no discovered code is executed here."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        result = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=result.tzinfo or dt.timezone.utc)
    except (ValueError, TypeError):
        return None


def age_hours(value: str | None) -> float:
    parsed = parse_time(value)
    if parsed is None:
        return float("inf")
    return max(0.0, (dt.datetime.now(dt.timezone.utc) - parsed).total_seconds() / 3600)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def default_state_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ARO"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "aro"


def run_argv(argv: list[str], cwd: str | None = None, timeout: int = 120) -> dict:
    """Run a reviewed argv without a shell and bound retained output."""
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(argv, cwd=cwd, shell=False, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + timeout
            timed_out = limited = False
            while process.poll() is None:
                timed_out = time.monotonic() > deadline
                limited = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > 8 * 1024 * 1024
                if timed_out or limited:
                    process.kill()
                    process.wait()
                    break
                time.sleep(0.02)
            out_size, err_size = os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size
            stdout.seek(max(0, out_size - 16384)); stderr.seek(max(0, err_size - 16384))
            message = stderr.read(16384).decode("utf-8", errors="replace")
            if timed_out or limited:
                message += "\nCommand interrupted by time/output limit. Child installers may still be active; verify package-manager state before any retry."
            return {"returncode": process.returncode, "stdout": stdout.read(16384).decode("utf-8", errors="replace"),
                    "stderr": message, "timed_out": timed_out, "truncated": limited or out_size > 16384 or err_size > 16384}
    except OSError as exc:
        return {"returncode": -1, "stdout": "", "stderr": str(exc), "timed_out": False, "truncated": False}
