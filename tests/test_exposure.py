import unittest
from aro_core.exposure import assess_findings, render_report
from aro_core.common import digest


def inbound_evidence():
    return {digest(("web", "CVE-2026-0001"))[:16]: {"attack_path": "inbound-service", "evidence": "The advisory identifies the enabled server request handler", "checked_at": "2099-01-01T00:00:00Z"}}


def inventory():
    return {"components": [{"id": "web", "name": "demo", "version": "1.0", "kind": "package"}],
            "network": {}, "coverage": []}


def advisory(vector="network", kev=False):
    return {"id": "CVE-2026-0001", "component_id": "web", "severity": "CRITICAL",
            "attack_vector": vector, "fixed_versions": ["1.2.3"], "summary": "Remote execution",
            "known_exploited": kev, "source_url": "https://osv.dev/vulnerability/CVE-2026-0001",
            "match_confidence": "confirmed"}


class ExposureTests(unittest.TestCase):
    def test_cgnat_alone_does_not_suppress_critical(self):
        rows = assess_findings(inventory(), [advisory()], {"network": {"cgnat": "confirmed"}})
        self.assertEqual(rows[0]["exposure"], "unknown")
        self.assertIn(rows[0]["priority"], ("immediate", "soon"))

    def test_ipv6_or_tunnel_prevents_cgnat_downgrade(self):
        config = {"network": {"cgnat": "confirmed", "public_ipv6": "yes", "tunnels": "yes"}}
        row = assess_findings(inventory(), [advisory()], config)[0]
        self.assertIn("IPv6", row["reason"])

    def test_verified_loopback_lowers_network_risk_but_not_local(self):
        config = {"network": {"bindings": {"web": {"reachability": "loopback",
                  "evidence": "Listener checked", "checked_at": "2099-01-01T00:00:00Z"}}}}
        config["network"]["finding_paths"] = inbound_evidence()
        network = assess_findings(inventory(), [advisory()], config)[0]
        local = assess_findings(inventory(), [advisory("local")], config)[0]
        self.assertEqual(network["priority"], "planned")
        self.assertIn(local["priority"], ("immediate", "soon"))

    def test_stale_reachability_is_unknown(self):
        config = {"network": {"bindings": {"web": {"reachability": "unreachable",
                  "evidence": "Old firewall check", "checked_at": "2001-01-01T00:00:00Z"}}}}
        self.assertEqual(assess_findings(inventory(), [advisory()], config)[0]["exposure"], "unknown")

    def test_known_exploitation_is_visible_for_lan_only(self):
        config = {"network": {"bindings": {"web": {"reachability": "lan",
                  "evidence": "LAN listener", "checked_at": "2099-01-01T00:00:00Z"}}}}
        row = assess_findings(inventory(), [advisory(kev=True)], config)[0]
        self.assertTrue(row["known_exploited"])
        self.assertEqual(row["priority"], "immediate")

    def test_failed_scan_is_not_clean(self):
        report = {"findings": [], "complete": False, "coverage": [{"status": "error", "collector": "osv", "detail": "offline"}]}
        text = render_report(report)
        self.assertIn("Incomplete", text)
        self.assertNotIn("safe", text.lower())

    def test_fresh_complete_cgnat_boundary_lowers_network_priority(self):
        config = {"network": {"cgnat": "confirmed", "public_ipv4": "no", "public_ipv6": "no",
            "inbound_forwarding": "no", "tunnels": "no", "boundary_checked_at": "2099-01-01T00:00:00Z", "finding_paths": inbound_evidence()}}
        row = assess_findings(inventory(), [advisory()], config)[0]
        self.assertEqual(row["exposure"], "restricted_inbound")
        self.assertEqual(row["priority"], "planned")
        local = assess_findings(inventory(), [advisory("local")], config)[0]
        self.assertEqual(local["priority"], "soon")

    def test_observed_tunnel_overrides_declared_cgnat_boundary(self):
        config = {"network": {"cgnat": "confirmed", "public_ipv4": "no", "public_ipv6": "no",
            "inbound_forwarding": "no", "tunnels": "no", "boundary_checked_at": "2099-01-01T00:00:00Z", "finding_paths": inbound_evidence()}}
        current = inventory()
        current["network"] = {"tunnels": [{"interface": "tailscale0"}]}
        self.assertEqual(assess_findings(current, [advisory()], config)[0]["exposure"], "unknown")

    def test_network_vector_alone_does_not_prove_inbound_attack_path(self):
        config = {"network": {"cgnat": "confirmed", "public_ipv4": "no", "public_ipv6": "no",
            "inbound_forwarding": "no", "tunnels": "no", "boundary_checked_at": "2099-01-01T00:00:00Z"}}
        row = assess_findings(inventory(), [advisory()], config)[0]
        self.assertEqual(row["priority"], "soon")
        self.assertEqual(row["attack_path"], "unknown")
        self.assertNotIn("reachable on the local", row["reason"])


if __name__ == "__main__":
    unittest.main()
