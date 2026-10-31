import copy
import json
import tempfile
import unittest
from pathlib import Path

from aro_core.state import StateStore, inventory_fingerprint, reconcile_inventory


def sample(version="1.0", stamp="2026-01-01T00:00:00Z"):
    return {"schema_version": 1, "scanned_at": stamp, "host": {"os": "linux"},
            "roots": ["/app"], "components": [{"id": "p1", "name": "demo", "version": version,
            "kind": "package", "source": "lockfile", "path": "/app/package-lock.json"}],
            "projects": [], "containers": [], "network": {"listeners": []},
            "coverage": [{"collector": "projects", "status": "ok", "detail": "checked"}]}


class StateTests(unittest.TestCase):
    def test_timestamp_and_pid_do_not_change_map(self):
        a, b = sample(), sample(stamp="2026-01-02T00:00:00Z")
        a["processes"] = [{"pid": 10, "name": "python", "exe": "/bin/python"}]
        b["processes"] = [{"pid": 20, "name": "python", "exe": "/bin/python"}]
        self.assertEqual(inventory_fingerprint(a), inventory_fingerprint(b))

    def test_added_removed_and_changed_versions(self):
        old, new = sample(), sample("2.0")
        old["components"].append({"id": "gone", "name": "old", "version": "1"})
        new["components"].append({"id": "new", "name": "new", "version": "1"})
        merged, delta = reconcile_inventory(old, new)
        self.assertEqual([x["id"] for x in delta["added"]], ["new"])
        self.assertEqual([x["id"] for x in delta["removed"]], ["gone"])
        self.assertEqual(delta["changed"][0]["before"]["version"], "1.0")
        self.assertEqual(merged["components"][1]["version"], "2.0")

    def test_partial_scan_preserves_unverified_components(self):
        old, new = sample(), sample()
        new["components"] = []
        new["coverage"][0]["status"] = "error"
        merged, delta = reconcile_inventory(old, new)
        self.assertEqual(delta["removed"], [])
        self.assertEqual(merged["components"][0]["evidence_status"], "stale")
        self.assertEqual(delta["missing_unverified"][0]["id"], "p1")

    def test_atomic_store_and_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            store = StateStore(Path(folder) / "aro")
            with store.lock():
                store.write("inventory.json", sample())
                self.assertEqual(store.read("inventory.json")["components"][0]["version"], "1.0")
                with self.assertRaises(RuntimeError):
                    with store.lock():
                        pass
            self.assertFalse((store.root / ".lock").exists())
            self.assertEqual(list(store.root.glob("*.tmp")), [])

    def test_store_rejects_escape_and_corrupt_json(self):
        with tempfile.TemporaryDirectory() as folder:
            store = StateStore(Path(folder))
            with self.assertRaises(ValueError):
                store.write("../escape.json", {})
            (store.root / "inventory.json").write_text("broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                store.read("inventory.json")

    def test_native_collector_hierarchy_preserves_failed_package_scan(self):
        old = sample()
        old["components"][0].update({"kind": "os-package", "source": "dpkg-query", "collector": "dpkg-query", "path": None})
        for collector, status in (("os-packages", "error"), ("host", "error"), ("os-packages", "unavailable")):
            new = sample()
            new["components"] = []
            new["coverage"] = [{"collector": collector, "status": status, "detail": "inaccessible"}]
            merged, delta = reconcile_inventory(old, new)
            self.assertEqual(delta["removed"], [])
            self.assertEqual(merged["components"][0]["evidence_status"], "stale")

    def test_optional_scanner_failure_does_not_hide_real_package_removal(self):
        old, new = sample(), sample()
        old["components"][0].update({"kind": "os-package", "source": "dpkg-query", "collector": "dpkg-query", "path": None})
        new["components"] = []
        new["coverage"] = [{"collector": "syft", "status": "unavailable", "detail": "not installed"}]
        merged, delta = reconcile_inventory(old, new)
        self.assertEqual(len(delta["removed"]), 1)
        self.assertEqual(merged["components"], [])

    def test_windows_registry_parent_failure_is_not_removal(self):
        old = sample()
        old["components"][0].update({"kind": "application", "source": "windows-registry", "collector": "windows-registry", "path": None})
        new = sample()
        new["components"] = []
        new["coverage"] = [{"collector": "windows-apps", "status": "error", "detail": "denied"}]
        merged, delta = reconcile_inventory(old, new)
        self.assertEqual(delta["removed"], [])
        self.assertEqual(merged["components"][0]["evidence_status"], "stale")


if __name__ == "__main__":
    unittest.main()
