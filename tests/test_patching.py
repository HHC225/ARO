import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
import venv
from pathlib import Path

from aro_core.common import digest
from aro_core.patching import PatchRefused, apply_plan, create_plan


def inventory(version="1.0.0"):
    return {"schema_version": 1, "host": {"os": "linux"}, "roots": ["/app"], "components": [
        {"id": "p", "name": "demo", "version": version, "ecosystem": "Debian:12",
         "kind": "os-package", "manager": "apt", "source": "dpkg", "path": "/var/lib/dpkg/status"}],
        "coverage": [], "network": {}}


def finding():
    return {"finding_id": "f", "component_id": "p", "id": "CVE-2026-0001", "fixed_versions": ["1.0.1"],
            "source_url": "https://security-tracker.debian.org/", "match_confidence": "confirmed"}


def resolver(name):
    return str(Path(tempfile.gettempdir()) / "aro-test-tools" / name)


def compare_runner(argv, **kwargs):
    if argv[1:2] != ["--compare-versions"]:
        raise AssertionError("A native Debian version comparison is required")
    return {"returncode": 0}


def preview_runner(*args, **kwargs):
    return {"returncode": 0, "stdout": "Inst demo [1.0.0] (1.0.1 vendor)\nConf demo (1.0.1 vendor)", "stderr": ""}


class PatchTests(unittest.TestCase):
    def plan(self):
        return create_plan(inventory(), finding(), "1.0.1", resolver=resolver, preview_runner=preview_runner, compare_runner=compare_runner)

    def test_exact_approved_native_arguments(self):
        plan = self.plan()
        self.assertEqual(plan["steps"][0]["argv"], [resolver("apt-get"), "install", "--assume-yes", "--only-upgrade", "--no-remove", "--", "demo=1.0.1"])
        calls = []
        result = apply_plan(plan, plan["plan_hash"], inventory(), runner=lambda argv, **kw: calls.append(argv) or {"returncode": 0},
                            rescan=lambda: inventory("1.0.1"), resolver=resolver, preview_runner=preview_runner)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["inventory"]["components"][0]["version"], "1.0.1")

    def test_missing_approval_and_tampering_never_execute(self):
        for mode in ("missing", "tampered"):
            plan, calls = self.plan(), []
            if mode == "tampered":
                plan["steps"][0]["argv"].append("other-package")
            with self.assertRaises(PatchRefused):
                apply_plan(plan, None if mode == "missing" else plan["plan_hash"], inventory(), runner=lambda *a, **kw: calls.append(a), resolver=resolver)
            self.assertEqual(calls, [])

    def test_rehashed_arbitrary_command_is_refused(self):
        plan = self.plan()
        plan["steps"][0]["argv"] = ["/bin/sh", "-c", "echo unsafe"]
        plan["plan_hash"] = digest({key: value for key, value in plan.items() if key != "plan_hash"})
        with self.assertRaises(PatchRefused):
            apply_plan(plan, plan["plan_hash"], inventory(), resolver=resolver)

    def test_inventory_change_refuses_old_approval(self):
        plan = self.plan()
        with self.assertRaises(PatchRefused):
            apply_plan(plan, plan["plan_hash"], inventory("1.0.2"), resolver=resolver)

    def test_unlisted_target_or_option_like_package_refused(self):
        with self.assertRaises(PatchRefused):
            create_plan(inventory(), finding(), "9.9.9", resolver=resolver)
        bad = inventory()
        bad["components"][0]["name"] = "--allow-unauthenticated"
        with self.assertRaises(PatchRefused):
            create_plan(bad, finding(), "1.0.1", resolver=resolver)

    def test_failed_patch_still_reinventories(self):
        plan, rescans = self.plan(), []
        result = apply_plan(plan, plan["plan_hash"], inventory(), runner=lambda *a, **kw: {"returncode": 1, "stderr": "failure"},
                            rescan=lambda: rescans.append(True) or inventory(), resolver=resolver, preview_runner=preview_runner)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(rescans, [True])
        self.assertIn("inventory", result)

    def test_success_without_target_version_is_unverified(self):
        plan = self.plan()
        result = apply_plan(plan, plan["plan_hash"], inventory(), runner=lambda *a, **kw: {"returncode": 0},
                            rescan=inventory, resolver=resolver, preview_runner=preview_runner)
        self.assertEqual(result["status"], "verification_failed")

    def test_lockfile_hash_change_invalidates_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            project = Path(folder)
            (project / "package.json").write_text('{"dependencies":{"demo":"1.0.0"}}', encoding="utf-8")
            lockfile = project / "package-lock.json"
            lockfile.write_text('{"lockfileVersion":3}', encoding="utf-8")
            inv = inventory()
            inv["components"][0].update({"manager": "npm", "ecosystem": "npm", "kind": "package", "source": "lockfile", "path": str(lockfile), "scope": "node_modules/demo",
                                          "metadata": {"project_path": str(project), "direct": True}})
            plan = create_plan(inv, finding(), "1.0.1", resolver=resolver)
            self.assertIn("--global=false", plan["steps"][0]["argv"])
            self.assertEqual(plan["steps"][0]["argv"][plan["steps"][0]["argv"].index("--prefix") + 1], str(project))
            lockfile.write_text('{"lockfileVersion":2}', encoding="utf-8")
            with self.assertRaises(PatchRefused):
                apply_plan(plan, plan["plan_hash"], inv, resolver=resolver)

    def test_changed_native_transaction_refuses_execution(self):
        plan = self.plan()
        calls = []
        changed = lambda *a, **kw: {"returncode": 0, "stdout": "Inst demo [1.0.0] (1.0.1 vendor)\nInst dependency (9.0 vendor)"}
        with self.assertRaises(PatchRefused):
            apply_plan(plan, plan["plan_hash"], inventory(), rescan=inventory, resolver=resolver,
                       runner=lambda *a, **kw: calls.append(a), preview_runner=changed)
        self.assertEqual(calls, [])

    def test_nested_npm_name_does_not_patch_direct_dependency(self):
        with tempfile.TemporaryDirectory() as folder:
            project = Path(folder)
            (project / "package.json").write_text('{"dependencies":{"demo":"2.0.0"}}', encoding="utf-8")
            lock = project / "package-lock.json"
            lock.write_text('{"lockfileVersion":3}', encoding="utf-8")
            inv = inventory()
            inv["components"][0].update({"manager": "npm", "ecosystem": "npm", "kind": "package", "source": "lockfile", "path": str(lock),
                "scope": "node_modules/parent/node_modules/demo", "metadata": {"project_path": str(project)}})
            with self.assertRaises(PatchRefused):
                create_plan(inv, finding(), "1.0.1", resolver=resolver)

    def test_debian_architecture_is_part_of_patch_target(self):
        inv = inventory()
        inv["components"][0]["metadata"] = {"architecture": "i386"}
        plan = create_plan(inv, finding(), "1.0.1", resolver=resolver, preview_runner=preview_runner, compare_runner=compare_runner)
        self.assertEqual(plan["steps"][0]["argv"][-1], "demo:i386=1.0.1")

    def test_venv_symlink_keeps_the_approved_python_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            env = Path(folder) / "venv"
            venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(env)
            executable = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            script = """import json, os, sys
from aro_core.patching import create_plan
c={'id':'p','name':'demo','version':'1.0.0','manager':'pip','path':sys.prefix,'metadata':{'interpreter':os.path.abspath(sys.executable),'environment_prefix':os.path.abspath(sys.prefix)}}
f={'component_id':'p','match_confidence':'confirmed','fixed_versions':['1.0.1']}
print(json.dumps(create_plan({'components':[c]}, f, '1.0.1')['steps'][0]['argv']))
"""
            output = subprocess.check_output([str(executable), "-c", script], text=True, env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "skills/aro/scripts")})
            argv = json.loads(output)
            self.assertEqual(os.path.normcase(argv[0]), os.path.normcase(str(executable)))
            self.assertIn("--prefix", argv)
            self.assertIn("-I", argv)
            self.assertEqual(os.path.normcase(argv[argv.index("--prefix") + 1]), os.path.normcase(str(env)))

    def test_inherited_python_distribution_requires_its_own_environment(self):
        inv = inventory()
        inv["components"][0].update({"manager": "pip", "path": str(Path.home() / "other-python"),
            "metadata": {"interpreter": sys.executable, "environment_prefix": sys.prefix}})
        with self.assertRaises(PatchRefused):
            create_plan(inv, finding(), "1.0.1", resolver=resolver)

    def test_truncated_transaction_preview_is_refused(self):
        truncated = lambda *a, **kw: {**preview_runner(), "truncated": True}
        with self.assertRaises(PatchRefused):
            create_plan(inventory(), finding(), "1.0.1", resolver=resolver, preview_runner=truncated, compare_runner=compare_runner)

    def test_native_version_order_refuses_downgrade(self):
        calls = []
        def older(argv, **kwargs):
            calls.append(argv)
            return {"returncode": 1}
        with self.assertRaises(PatchRefused):
            create_plan(inventory(), finding(), "1.0.1", resolver=resolver, compare_runner=older, preview_runner=preview_runner)
        self.assertEqual(calls, [[resolver("dpkg"), "--compare-versions", "1.0.0", "lt", "1.0.1"]])


if __name__ == "__main__":
    unittest.main()
