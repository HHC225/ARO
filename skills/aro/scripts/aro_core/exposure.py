"""Rank observed vulnerabilities without confusing network assumptions with proof."""

from __future__ import annotations

import ipaddress

from .common import age_hours, digest

_PRIORITY = {"immediate": 0, "soon": 1, "planned": 2, "review": 3}
_SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _exposure(component: dict, inventory: dict, config: dict) -> tuple[str, str]:
    network = config.get("network", {})
    bindings = network.get("bindings", {})
    evidence = bindings.get(component["id"], {})
    if evidence and evidence.get("evidence") and age_hours(evidence.get("checked_at")) <= network.get("evidence_ttl_hours", 168):
        value = evidence.get("reachability", "unknown")
        if value in {"internet", "lan", "loopback", "unreachable"}:
            return value, str(evidence["evidence"])
    for row in inventory.get("network", {}).get("listeners", []):
        if component["id"] in row.get("component_ids", []):
            address = str(row.get("address", row.get("local_address", "")))
            if address in {"127.0.0.1", "::1", "localhost"}:
                # A loopback listener does not establish that a proxy/tunnel is absent.
                return "unknown", "A loopback listener was observed; proxy and tunnel reachability is unverified."
    observed = inventory.get("network", {})
    contradictory_route = bool(observed.get("tunnels"))
    for row in observed.get("addresses", []):
        try:
            contradictory_route = contradictory_route or ipaddress.ip_address(row.get("address", "")).is_global
        except ValueError:
            pass
    tunnel_processes = {"cloudflared", "ngrok", "frpc", "tailscaled", "zerotier-one", "bore"}
    contradictory_route = contradictory_route or any(str(row.get("name", "")).lower().removesuffix(".exe") in tunnel_processes for row in inventory.get("processes", []))
    fresh_boundary = age_hours(network.get("boundary_checked_at")) <= network.get("evidence_ttl_hours", 168)
    no_public_routes = (network.get("cgnat") == "confirmed" and all(network.get(key) == "no" for key in
        ("public_ipv4", "public_ipv6", "inbound_forwarding", "tunnels")))
    if fresh_boundary and no_public_routes and not contradictory_route:
        return "restricted_inbound", "Current user-confirmed CGNAT and absence of public IPv4/IPv6, forwarding and tunnels restrict direct inbound internet access; LAN access is still possible."
    return "unknown", "External reachability has not been verified."


def assess_findings(inventory: dict, advisories: list[dict], config: dict | None = None) -> list[dict]:
    config = config or {}
    components = {row["id"]: row for row in inventory.get("components", [])}
    findings = []
    seen = set()
    for advisory in advisories:
        component = components.get(advisory.get("component_id"))
        if component is None:
            continue
        identity = (component["id"], advisory.get("id", "unknown"))
        if identity in seen:
            continue
        seen.add(identity)
        severity = str(advisory.get("severity") or "UNKNOWN").upper()
        vector = str(advisory.get("attack_vector") or "unknown").lower()
        kev = bool(advisory.get("known_exploited"))
        exposure, evidence = _exposure(component, inventory, config)
        finding_id = digest(identity)[:16]
        path_record = config.get("network", {}).get("finding_paths", {}).get(finding_id, {})
        attack_path = "unknown"
        if path_record.get("evidence") and age_hours(path_record.get("checked_at")) <= config.get("network", {}).get("evidence_ttl_hours", 168):
            attack_path = path_record.get("attack_path", "unknown")
        confidence = advisory.get("match_confidence", "unknown")
        confirmed = confidence in {"confirmed", "exact", "high", "vendor", "version", "exact_version", "affected", "vendor-source-package", "vendor-package", "vendor_applicability"}
        priority = "immediate" if kev else ("soon" if _SEVERITY.get(severity, 0) >= 3 else "planned")
        reason = "Known exploitation is reported." if kev else "Patch the affected version."
        if not confirmed or component.get("evidence_status") == "stale":
            priority = "review"
            reason = "Confirm the affected version; available inventory or matching evidence is incomplete."
        elif vector == "network" and attack_path == "outbound-client":
            reason = "Outbound client traffic can reach the attack path; CGNAT does not prevent it."
        elif vector == "network" and attack_path == "inbound-service" and exposure in {"loopback", "unreachable", "restricted_inbound"}:
            priority = "soon" if kev else "planned"
            reason = "Confirmed inbound-service attack conditions and access restrictions reduce direct remote exposure; update during planned maintenance."
        elif vector == "local":
            reason = "Local access or code execution is needed; CGNAT does not prevent this attack path."
        elif vector == "adjacent":
            reason = "The attack requires access to the adjacent network; internet NAT is not a sufficient control."
        elif vector == "physical":
            priority = "soon" if kev else "planned"
            reason = "The reported attack requires physical access."
        elif exposure == "internet":
            priority = "immediate" if _SEVERITY.get(severity, 0) >= 4 or kev else priority
            reason = "The affected component is confirmed reachable from the internet."
        elif exposure == "lan":
            if vector == "network" and attack_path == "inbound-service" and not kev:
                priority = "planned"
            reason = "The component is reachable on the local network; other local devices remain an attack path."
        elif exposure in {"loopback", "unreachable", "restricted_inbound"}:
            reason = "Inbound access is restricted; whether that limits this vulnerability's attack path is unverified."
        elif exposure == "unknown":
            reason = "The affected version is present; external reachability is unverified."
        network = config.get("network", {})
        if network.get("cgnat") == "confirmed" and exposure == "unknown":
            if network.get("public_ipv6") == "yes" or network.get("tunnels") == "yes":
                reason += " IPv6 or a tunnel may bypass the IPv4 CGNAT boundary."
            else:
                reason += " CGNAT alone does not rule out IPv6, tunnels or local access."
        row = dict(advisory)
        row.update({"finding_id": finding_id, "component": component["name"], "attack_path": attack_path,
                    "installed_version": component.get("version"), "priority": priority,
                    "severity": severity, "exposure": exposure, "exposure_evidence": evidence,
                    "reason": reason, "known_exploited": kev,
                    "fixed_versions": list(dict.fromkeys(advisory.get("fixed_versions") or []))})
        findings.append(row)
    return sorted(findings, key=lambda row: (_PRIORITY[row["priority"]], -_SEVERITY.get(row["severity"], 0), row["component"], row["id"]))


def render_report(report: dict, limit: int = 20) -> str:
    findings = report.get("findings", [])
    complete = report.get("complete", False)
    heading = "ARO check complete" if complete else "ARO check — Incomplete coverage"
    lines = [heading]
    delta = report.get("delta", {})
    if delta:
        lines.append(f"Map: +{len(delta.get('added', []))} added, {len(delta.get('changed', []))} changed, {len(delta.get('removed', []))} removed; {len(delta.get('missing_unverified', []))} unverified.")
    if not findings:
        lines.append("No matching advisories were found in the completed sources." if complete else
                     "No matching advisories were returned; incomplete checks prevent a clean assessment.")
    for row in findings[:limit]:
        fixes = row.get("fixed_versions", [])
        fix = ", ".join(str(item) for item in fixes[:4]) or "no confirmed fix listed"
        if len(fixes) > 4:
            fix += f" (+{len(fixes) - 4} other branches)"
        lines.append(f"[{row['priority'].upper()}] {row['component']} {row.get('installed_version') or '?'} → {fix} | {row['id']} | {row['reason']}")
        lines.append(f"  Finding: {row['finding_id']} | {row.get('source_url') or 'See report.json for source evidence'}")
    if len(findings) > limit:
        lines.append(f"{len(findings) - limit} further findings are stored in report.json.")
    gaps = [row for row in report.get("coverage", []) if row.get("status") not in {"ok", "not_applicable"}]
    if gaps:
        lines.append(f"Coverage notes: {len(gaps)}. " + "; ".join(f"{row.get('collector', row.get('source', 'source'))}: {row.get('detail', row.get('status', 'unknown'))}" for row in gaps[:3]))
    if report.get("checked_at"):
        lines.append(f"Checked: {report['checked_at']}")
    dates = sorted(row["fetched_at"] for row in report.get("sources", []) if row.get("fetched_at"))
    if dates:
        lines.append(f"Oldest source data used: {dates[0]}. Use check --refresh to bypass the fresh-cache TTL.")
    return "\n".join(lines)
