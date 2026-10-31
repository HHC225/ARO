"""One workflow for first-run initialization, checks, plans and approved changes."""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path

from . import __version__
from .advisories import build_source_plan, query_advisories
from .common import age_hours, default_state_dir, utc_now
from .exposure import assess_findings, render_report
from .inventory import collect_inventory
from .patching import PatchRefused, apply_plan, create_plan
from .state import StateStore, reconcile_inventory

DEFAULT_CONFIG = {
    "schema_version": 1, "roots": [], "exclude_packages": [], "cache_ttl_hours": 6,
    "max_cache_age_hours": 168, "scan": {"max_files": 100000, "max_depth": 12, "command_timeout": 20,
                                       "include_system": True, "include_docker": True, "enable_syft": True},
    "network": {"cgnat": "unknown", "public_ipv4": "unknown", "public_ipv6": "unknown",
                "inbound_forwarding": "unknown", "tunnels": "unknown", "trusted_lan": False,
                "evidence_ttl_hours": 168, "bindings": {}, "finding_paths": {}}
}


def _config(store: StateStore) -> dict:
    supplied = store.read("config.json", {})
    if not isinstance(supplied, dict):
        raise ValueError("config.json must contain a JSON object.")
    config = copy.deepcopy(DEFAULT_CONFIG)
    for key, value in supplied.items():
        if key in {"scan", "network"}:
            if not isinstance(value, dict):
                raise ValueError(f"Configuration {key} must be an object.")
            config[key].update(value)
        else:
            config[key] = value
    for key in ("roots", "exclude_packages"):
        if not isinstance(config[key], list) or not all(isinstance(item, str) for item in config[key]):
            raise ValueError(f"Configuration {key} must be a list of strings.")
    for key in ("cache_ttl_hours", "max_cache_age_hours"):
        if not isinstance(config[key], (int, float)) or not 0 < config[key] <= 24 * 365:
            raise ValueError(f"Invalid configuration value: {key}")
    if not isinstance(config["network"].get("bindings"), dict):
        raise ValueError("network.bindings must be an object.")
    if not isinstance(config["network"].get("finding_paths"), dict):
        raise ValueError("network.finding_paths must be an object.")
    for key, maximum in (("max_files", 10000000), ("max_depth", 100), ("command_timeout", 300)):
        if not isinstance(config["scan"].get(key), int) or not 1 <= config["scan"][key] <= maximum:
            raise ValueError(f"Invalid scan option: {key}")
    return config


def _refresh(store: StateStore, config: dict, roots=None) -> tuple[dict, dict]:
    if roots:
        config["roots"] = sorted(set(str(Path(root).expanduser().resolve()) for root in roots))
    options = dict(config["scan"])
    options["state_dir"] = str(store.root)
    current = collect_inventory(config.get("roots", []), options)
    if not isinstance(current, dict) or not isinstance(current.get("components"), list):
        raise ValueError("The inventory collector did not produce a valid software map.")
    previous = store.read("inventory.json")
    inventory, delta = reconcile_inventory(previous, current)
    inventory["source_plan"] = build_source_plan(inventory, config)
    store.write("config.json", config)
    store.write("inventory.json", inventory)
    store.write("delta.json", delta)
    return inventory, delta


def _coverage(inventory: dict, queried: dict) -> list[dict]:
    rows = list(inventory.get("coverage", [])) + list(queried.get("coverage", []))
    represented = {str(row.get("collector", row.get("source", ""))) for row in rows}
    for source in queried.get("sources", []):
        name = str(source.get("source", source.get("id", "advisory-source")))
        if source.get("status") not in {"ok", "not_applicable"} and name not in represented:
            rows.append({"collector": name, "status": source.get("status", "unknown"),
                         "detail": source.get("detail", "Source did not complete with fresh data.")})
    return rows


def _check(store: StateStore, config: dict, args, inventory=None, delta=None) -> dict:
    if inventory is None:
        inventory, delta = _refresh(store, config, getattr(args, "root", None))
    options = dict(config)
    options["offline"] = bool(getattr(args, "offline", False))
    options["force_refresh"] = bool(getattr(args, "refresh", False))
    queried = query_advisories(inventory, store.path("cache"), options)
    rows = _coverage(inventory, queried)
    complete = all(row.get("status") in {"ok", "not_applicable"} for row in rows)
    complete = complete and all(row.get("status") in {"ok", "not_applicable"} for row in queried.get("sources", []))
    if any(row.get("evidence_status") == "stale" for row in inventory.get("components", [])):
        complete = False
        rows.append({"collector": "reconciliation", "status": "partial", "detail": "Previously observed components could not be reverified."})
    report = {"schema_version": 1, "checked_at": utc_now(), "inventory_fingerprint": inventory["fingerprint"],
              "complete": complete, "delta": delta or {}, "findings": assess_findings(inventory, queried.get("advisories", []), config),
              "source_plan": queried.get("source_plan", inventory.get("source_plan", [])),
              "sources": queried.get("sources", []), "coverage": rows,
              "summary": {"components": len(inventory.get("components", [])), "projects": len(inventory.get("projects", [])),
                          "containers": len(inventory.get("containers", []))}}
    report["summary"]["findings"] = len(report["findings"])
    store.write("report.json", report)
    return report


def _check_exit(report: dict, threshold: str) -> int:
    if not report.get("complete"):
        return 2
    if threshold == "none":
        return 0
    severities = {"critical": {"CRITICAL"}, "high": {"HIGH", "CRITICAL"}}
    if threshold == "any":
        return int(bool(report.get("findings")))
    return int(any(row.get("severity") in severities[threshold] for row in report.get("findings", [])))


def _output(value, style: str, text: str | None = None):
    if style == "json":
        print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False))
    else:
        print(text if text is not None else json.dumps(value, indent=2, ensure_ascii=False))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aro", description="Inventory this machine, check relevant advisories, and plan approved updates.")
    parser.add_argument("--version", action="version", version=f"ARO {__version__}")
    subs = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "scan", "check", "sources", "config", "exposure", "plan", "apply"):
        sub = subs.add_parser(name)
        sub.add_argument("--state-dir", type=Path, default=default_state_dir())
        sub.add_argument("--format", choices=("text", "json"), default="text")
        if name in {"init", "scan", "check", "sources", "plan"}:
            sub.add_argument("--root", action="append", help="Project/application root; repeat to add more. Persisted for later scans.")
        if name == "check":
            freshness = sub.add_mutually_exclusive_group()
            freshness.add_argument("--offline", action="store_true", help="Use cached advisories and report their age; no online refresh.")
            freshness.add_argument("--refresh", action="store_true", help="Bypass the fresh-cache TTL and request current source responses.")
            sub.add_argument("--fail-on", choices=("none", "any", "high", "critical"), default="none")
        if name == "config":
            sub.add_argument("--show", action="store_true")
        if name == "plan":
            sub.add_argument("--finding", required=True)
            sub.add_argument("--target-version", required=True)
        if name == "apply":
            sub.add_argument("--plan", type=Path, required=True)
            sub.add_argument("--approve", help="Full plan SHA-256, only after the user approves this exact change.")
            sub.add_argument("--offline", action="store_true", help="Use cached advisory data for the post-patch check.")
        if name == "exposure":
            sub.add_argument("--cgnat", choices=("unknown", "confirmed", "absent"))
            for field in ("public-ipv4", "public-ipv6", "inbound-forwarding", "tunnels"):
                sub.add_argument("--" + field, choices=("unknown", "yes", "no"))
            sub.add_argument("--component")
            sub.add_argument("--finding")
            sub.add_argument("--attack-path", choices=("inbound-service", "outbound-client", "local", "unknown"))
            sub.add_argument("--reachability", choices=("internet", "lan", "loopback", "unreachable", "unknown"))
            sub.add_argument("--evidence")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = _parser().parse_args(argv or ["check"])
    try:
        store = StateStore(args.state_dir)
        with store.lock():
            config = _config(store)
            if args.command in {"init", "scan"}:
                inventory, delta = _refresh(store, config, args.root)
                result = {"inventory": inventory, "delta": delta}
                _output(result, args.format, f"Software map saved: {len(inventory['components'])} components; {len(inventory.get('coverage', []))} coverage entries. Run 'check' for advisory results.")
                return 0
            if args.command == "check":
                report = _check(store, config, args)
                _output(report, args.format, render_report(report))
                return _check_exit(report, args.fail_on)
            if args.command == "sources":
                inventory, _ = _refresh(store, config, args.root)
                _output({"source_plan": inventory["source_plan"]}, args.format)
                return 0
            if args.command == "config":
                store.write("config.json", config)
                _output(config, args.format)
                return 0
            if args.command == "exposure":
                network = config["network"]
                facts = ("cgnat", "public_ipv4", "public_ipv6", "inbound_forwarding", "tunnels")
                for key in facts:
                    if getattr(args, key) is not None:
                        network[key] = getattr(args, key)
                if all(getattr(args, key) is not None for key in facts):
                    network["boundary_checked_at"] = utc_now()
                elif any(getattr(args, key) is not None for key in facts):
                    network.pop("boundary_checked_at", None)
                if args.component or args.reachability:
                    if not (args.component and args.reachability and args.evidence):
                        raise ValueError("A component exposure assessment requires --component, --reachability and --evidence.")
                    inventory = store.read("inventory.json", {})
                    if args.component not in {row["id"] for row in inventory.get("components", [])}:
                        raise ValueError("Component ID is not present in the current software map.")
                    network["bindings"][args.component] = {"reachability": args.reachability, "evidence": args.evidence, "checked_at": utc_now()}
                if args.finding or args.attack_path:
                    if not (args.finding and args.attack_path and args.evidence):
                        raise ValueError("An attack-path assessment requires --finding, --attack-path and --evidence.")
                    report = store.read("report.json", {})
                    if args.finding not in {row["finding_id"] for row in report.get("findings", [])}:
                        raise ValueError("Finding ID is not present in the latest report.")
                    network["finding_paths"][args.finding] = {"attack_path": args.attack_path, "evidence": args.evidence, "checked_at": utc_now()}
                network["checked_at"] = utc_now()
                store.write("config.json", config)
                _output(network, args.format, "Network observations saved. Component-specific evidence expires after seven days; run check to refresh priorities.")
                return 0
            if args.command == "plan":
                report = store.read("report.json", {})
                if age_hours(report.get("checked_at")) > 24:
                    raise PatchRefused("Run a fresh check before creating a patch plan.")
                finding = next((row for row in report.get("findings", []) if row.get("finding_id") == args.finding), None)
                if finding is None:
                    raise PatchRefused("Finding not found in report.json; use the finding ID printed by check.")
                inventory, _ = _refresh(store, config, args.root)
                component = next((row for row in inventory["components"] if row["id"] == finding.get("component_id")), {})
                if component.get("version") != finding.get("installed_version"):
                    raise PatchRefused("The affected version changed since the report. Run check again.")
                plan = create_plan(inventory, finding, args.target_version)
                path = store.write(f"plans/{plan['plan_hash']}.json", plan)
                _output({"plan_path": str(path), "plan": plan}, args.format,
                        f"Patch plan: {plan['component_name']} {plan['installed_version']} → {plan['target_version']}\n"
                        + "\n".join(f"Command (argv): {json.dumps(step['argv'])}" for step in plan["steps"])
                        + ("\nNative transaction:\n" + "\n".join(plan["native_preview"]["changes"]) if plan.get("native_preview") else "")
                        + "\n" + "\n".join(plan["warnings"])
                        + f"\nPlan: {path}\nApproval hash: {plan['plan_hash']}\nExpires: {plan['expires_at']}\nAsk the user to approve this exact plan before apply.")
                return 0
            if args.command == "apply":
                if not args.approve:
                    raise PatchRefused("Explicit user approval is required: pass the reviewed plan's full hash with --approve.")
                if args.plan.stat().st_size > 1024 * 1024:
                    raise PatchRefused("Patch plan exceeds the maximum size.")
                with args.plan.open(encoding="utf-8") as stream:
                    plan = json.load(stream)
                if not isinstance(plan, dict):
                    raise PatchRefused("Invalid patch plan.")
                inventory, _ = _refresh(store, config)
                stamp = utc_now().replace(":", "").replace("-", "")
                journal_path = f"history/{stamp}-{args.approve[:12]}.json"
                result = apply_plan(plan, args.approve, inventory,
                    rescan=lambda: _refresh(store, config)[0],
                    backup_dir=store.path(f"history/{stamp}-{args.approve[:12]}-backup"),
                    journal=lambda item: store.write(journal_path, item))
                if result.get("inventory"):
                    post = _check(store, config, args, inventory=result["inventory"], delta=store.read("delta.json", {}))
                    result["post_check"] = {"complete": post["complete"], "findings": len(post["findings"])}
                    store.write(journal_path, result)
                _output(result, args.format, f"Patch result: {result['status']}. Observed version: {result.get('observed_version', 'unknown')}.\n"
                        + result["service_health"] + f"\nJournal: {store.path(journal_path)}")
                return 0 if result["status"] == "applied" else 2
    except PatchRefused as exc:
        _output({"error": str(exc), "status": "refused"}, args.format, f"Patch refused: {exc}")
        return 3
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        _output({"error": str(exc), "status": "error"}, args.format, f"ARO could not complete: {exc}")
        return 2
    return 2
