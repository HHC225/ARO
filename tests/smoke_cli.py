"""Native-platform CLI smoke test, including first-run and offline behavior."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run():
    repo = Path(__file__).resolve().parents[1]
    entry = repo / "skills" / "aro" / "scripts" / "aro.py"
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        project, state = root / "app", root / "state"
        project.mkdir(); state.mkdir()
        (project / "package.json").write_text('{"dependencies":{"lodash":"4.17.11"}}', encoding="utf-8")
        (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.11"}}}), encoding="utf-8")
        (state / "config.json").write_text(json.dumps({"roots": [str(project)], "scan": {"include_system": False,
            "include_docker": False, "discover_services": False}}), encoding="utf-8")
        args = [sys.executable, "-I", str(entry)]
        for command in ("scan", "scan", "check"):
            extra = ["--offline"] if command == "check" else []
            result = subprocess.run(args + [command, "--state-dir", str(state), "--format", "json"] + extra,
                                    text=True, capture_output=True, timeout=30)
            if result.returncode != (2 if command == "check" else 0):
                raise AssertionError(f"Unexpected exit {result.returncode}: {result.stdout} {result.stderr}")
            parsed = json.loads(result.stdout)
            if command == "check":
                assert parsed["complete"] is False
            else:
                assert any(row["name"] == "lodash" for row in parsed["inventory"]["components"])
        saved = json.loads((state / "delta.json").read_text(encoding="utf-8"))
        assert saved["map_changed"] is False, saved
        wrapper = repo / "skills" / "aro" / "scripts" / ("aro.ps1" if os.name == "nt" else "aro.sh")
        launcher = ["powershell", "-NoProfile", "-File", str(wrapper)] if os.name == "nt" else ["bash", str(wrapper)]
        result = subprocess.run(launcher + ["--version"], text=True, capture_output=True, timeout=30)
        assert result.returncode == 0 and "ARO" in result.stdout, (result.stdout, result.stderr)
    print("Native CLI smoke passed: first-run map, unchanged rescan, offline coverage and platform launcher.")


if __name__ == "__main__":
    run()
