import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aro_core.cli import main


def scan(version="1.0"):
    return {"schema_version": 1, "scanned_at": "2026-01-01T00:00:00Z", "host": {"os": "linux"},
            "roots": ["/app"], "components": [{"id": "p", "name": "sample", "version": version,
            "kind": "package", "ecosystem": "PyPI", "source": "installed", "collector": "python"}],
            "network": {}, "coverage": [{"collector": "python", "status": "ok", "detail": "checked"}]}


class CLITests(unittest.TestCase):
    def invoke(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(argv)
        return code, json.loads(output.getvalue())

    @patch("aro_core.cli.query_advisories")
    @patch("aro_core.cli.build_source_plan", return_value=[{"id": "osv", "source": "osv"}])
    @patch("aro_core.cli.collect_inventory")
    def test_first_use_then_unchanged_and_changed_map(self, collect, routes, query):
        collect.return_value = scan()
        query.return_value = {"advisories": [], "sources": [{"source": "osv", "status": "ok"}], "coverage": []}
        with tempfile.TemporaryDirectory() as folder:
            args = ["check", "--state-dir", folder, "--format", "json", "--root", "/app"]
            code, first = self.invoke(args)
            self.assertEqual(code, 0)
            self.assertTrue(first["delta"]["first_run"])
            code, second = self.invoke(args)
            self.assertFalse(second["delta"]["map_changed"])
            collect.return_value = scan("2.0")
            code, third = self.invoke(args)
            self.assertEqual(len(third["delta"]["changed"]), 1)
            self.assertEqual(json.loads((Path(folder) / "inventory.json").read_text())["components"][0]["version"], "2.0")
            self.assertEqual(collect.call_count, 3)
            self.assertEqual(query.call_count, 3)

    @patch("aro_core.cli.query_advisories", return_value={"advisories": [], "sources": [{"source": "osv", "status": "error"}], "coverage": []})
    @patch("aro_core.cli.build_source_plan", return_value=[])
    @patch("aro_core.cli.collect_inventory", return_value=scan())
    def test_failed_source_returns_incomplete(self, *unused):
        with tempfile.TemporaryDirectory() as folder:
            code, result = self.invoke(["check", "--state-dir", folder, "--format", "json"])
            self.assertEqual(code, 2)
            self.assertFalse(result["complete"])

    def test_missing_approval_returns_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "plan.json"
            path.write_text("{}", encoding="utf-8")
            code, result = self.invoke(["apply", "--state-dir", folder, "--format", "json", "--plan", str(path)])
            self.assertEqual(code, 3)
            self.assertIn("approval", result["error"].lower())

    def test_network_evidence_requires_text(self):
        with tempfile.TemporaryDirectory() as folder:
            code, result = self.invoke(["exposure", "--state-dir", folder, "--format", "json", "--component", "p", "--reachability", "unreachable"])
            self.assertEqual(code, 2)
            self.assertIn("evidence", result["error"].lower())

    def test_partial_network_edit_does_not_renew_stale_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps({"network": {"cgnat": "confirmed", "public_ipv4": "no", "public_ipv6": "no",
                "inbound_forwarding": "no", "tunnels": "no", "boundary_checked_at": "2001-01-01T00:00:00Z"}}), encoding="utf-8")
            code, result = self.invoke(["exposure", "--state-dir", folder, "--format", "json", "--cgnat", "confirmed"])
            self.assertEqual(code, 0)
            self.assertNotIn("boundary_checked_at", result)


if __name__ == "__main__":
    unittest.main()
