"""Unit tests for the risk engine and related modules — Person B's tests.

Run with:
    python -m pytest tests/test_risk.py -v
"""

from __future__ import annotations

import sys
import os

# Ensure the project root is on the path when running tests directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from scanner.risk import assess_risk, get_severity, summarise
from scanner.protocols import INSECURE_PROTOCOLS
from scanner.banner import grab_banner, identify_service


# ── get_severity ─────────────────────────────────────────────────────────────

class TestGetSeverity:
    def test_score_10_is_critical(self):
        assert get_severity(10) == "CRITICAL"

    def test_score_9_is_critical(self):
        assert get_severity(9) == "CRITICAL"

    def test_score_8_is_high(self):
        assert get_severity(8) == "HIGH"

    def test_score_7_is_high(self):
        assert get_severity(7) == "HIGH"

    def test_score_6_is_medium(self):
        assert get_severity(6) == "MEDIUM"

    def test_score_4_is_medium(self):
        assert get_severity(4) == "MEDIUM"

    def test_score_3_is_low(self):
        assert get_severity(3) == "LOW"

    def test_score_1_is_low(self):
        assert get_severity(1) == "LOW"

    def test_score_0_is_info(self):
        assert get_severity(0) == "INFO"

    def test_score_11_is_info(self):
        assert get_severity(11) == "INFO"


# ── protocols database ────────────────────────────────────────────────────────

class TestProtocolDatabase:
    REQUIRED_PORTS = [21, 23, 25, 69, 80, 110, 143, 161, 389, 512, 513, 2049]

    def test_all_required_ports_present(self):
        for port in self.REQUIRED_PORTS:
            assert port in INSECURE_PROTOCOLS, f"Port {port} missing from INSECURE_PROTOCOLS"

    def test_each_entry_has_required_keys(self):
        for port, meta in INSECURE_PROTOCOLS.items():
            for key in ("name", "risk", "reason", "replace"):
                assert key in meta, f"Port {port} missing key '{key}'"

    def test_risk_scores_in_valid_range(self):
        for port, meta in INSECURE_PROTOCOLS.items():
            score = int(meta["risk"])
            assert 1 <= score <= 10, f"Port {port} has out-of-range risk score {score}"

    def test_telnet_is_critical(self):
        assert INSECURE_PROTOCOLS[23]["risk"] >= 9

    def test_ftp_is_critical(self):
        assert INSECURE_PROTOCOLS[21]["risk"] >= 9

    def test_http_is_high(self):
        assert INSECURE_PROTOCOLS[80]["risk"] >= 7

    def test_smtp_is_medium_or_above(self):
        assert INSECURE_PROTOCOLS[25]["risk"] >= 4


# ── assess_risk ───────────────────────────────────────────────────────────────

class TestAssessRisk:
    def _make_port(self, port: int, banner: str = "") -> dict:
        return {"port": port, "state": "open", "banner": banner}

    def test_empty_input_returns_empty(self):
        assert assess_risk([]) == []

    def test_safe_port_not_flagged(self):
        # Port 22 (SSH) is not in the insecure database
        results = assess_risk([self._make_port(22)])
        assert results == []

    def test_telnet_is_flagged(self):
        results = assess_risk([self._make_port(23)])
        assert len(results) == 1
        assert results[0]["port"] == 23
        assert results[0]["severity"] == "CRITICAL"

    def test_ftp_is_flagged(self):
        results = assess_risk([self._make_port(21)])
        assert len(results) == 1
        assert results[0]["severity"] == "CRITICAL"

    def test_http_is_flagged(self):
        results = assess_risk([self._make_port(80)])
        assert len(results) == 1
        assert results[0]["severity"] == "HIGH"

    def test_multiple_insecure_ports(self):
        ports = [self._make_port(p) for p in [21, 23, 80, 110]]
        results = assess_risk(ports)
        assert len(results) == 4

    def test_results_sorted_by_risk_descending(self):
        ports = [self._make_port(p) for p in [80, 23, 25]]  # scores: 7, 10, 6
        results = assess_risk(ports)
        scores = [r["risk"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_banner_preserved_in_finding(self):
        banner = "220 vsftpd 3.0.5"
        results = assess_risk([self._make_port(21, banner)])
        assert results[0]["banner"] == banner

    def test_host_key_preserved(self):
        entry = {"port": 23, "state": "open", "banner": "", "host": "192.168.1.1"}
        results = assess_risk([entry])
        assert results[0]["host"] == "192.168.1.1"

    def test_finding_has_all_required_keys(self):
        results = assess_risk([self._make_port(23)])
        required = {"port", "name", "risk", "severity", "reason", "replace", "banner"}
        assert required.issubset(results[0].keys())

    def test_mixed_safe_and_insecure(self):
        ports = [self._make_port(p) for p in [22, 443, 23, 8080, 21]]
        results = assess_risk(ports)
        flagged_ports = {r["port"] for r in results}
        # SSH (22) and HTTPS (443) and 8080 should NOT be flagged
        assert 22 not in flagged_ports
        assert 443 not in flagged_ports
        # Telnet and FTP should be flagged
        assert 23 in flagged_ports
        assert 21 in flagged_ports


# ── summarise ─────────────────────────────────────────────────────────────────

class TestSummarise:
    def _finding(self, severity: str, score: int) -> dict:
        return {"severity": severity, "risk": score}

    def test_empty_findings(self):
        result = summarise([])
        assert result["total"] == 0
        assert result["critical"] == 0
        assert result["max_score"] == 0

    def test_counts_by_severity(self):
        findings = [
            self._finding("CRITICAL", 10),
            self._finding("CRITICAL", 9),
            self._finding("HIGH", 8),
            self._finding("MEDIUM", 5),
            self._finding("LOW", 2),
        ]
        result = summarise(findings)
        assert result["total"] == 5
        assert result["critical"] == 2
        assert result["high"] == 1
        assert result["medium"] == 1
        assert result["low"] == 1

    def test_max_score(self):
        findings = [self._finding("HIGH", 7), self._finding("CRITICAL", 10)]
        result = summarise(findings)
        assert result["max_score"] == 10


# ── banner identify_service ───────────────────────────────────────────────────

class TestIdentifyService:
    def test_ssh_banner(self):
        assert identify_service("SSH-2.0-OpenSSH_9.1") == "SSH"

    def test_ftp_banner(self):
        assert identify_service("220 vsftpd 3.0.5") == "FTP/SMTP"

    def test_pop3_banner(self):
        assert identify_service("+OK POP3 ready") == "POP3"

    def test_imap_banner(self):
        assert identify_service("* OK IMAP4rev1 ready") == "IMAP"

    def test_empty_banner(self):
        assert identify_service("") == "Unknown"

    def test_unknown_banner(self):
        assert identify_service("GARBLED DATA XYZ") == "Unknown"


# ── integration: full pipeline ────────────────────────────────────────────────

class TestIntegration:
    """End-to-end test of the Person B pipeline without network access."""

    def test_full_pipeline_no_network(self):
        """Simulate data coming from Person A and run through Person B modules."""
        # Simulated output from Person A's scanner
        fake_open_ports = [
            {"port": 23,  "state": "open", "banner": ""},
            {"port": 21,  "state": "open", "banner": "220 vsftpd 3.0.5"},
            {"port": 80,  "state": "open", "banner": "HTTP/1.1 200 OK"},
            {"port": 22,  "state": "open", "banner": "SSH-2.0-OpenSSH_9.1"},
            {"port": 443, "state": "open", "banner": ""},
        ]

        # Run through risk engine
        findings = assess_risk(fake_open_ports)

        # Only insecure ports should appear
        flagged = {f["port"] for f in findings}
        assert flagged == {21, 23, 80}
        assert 22 not in flagged
        assert 443 not in flagged

        # Summarise
        stats = summarise(findings)
        assert stats["total"] == 3
        assert stats["critical"] >= 1   # Telnet + FTP are CRITICAL

        # JSON serialisation (no file I/O)
        import json
        payload = {"findings": findings, "summary": stats}
        serialised = json.dumps(payload, indent=2)
        loaded = json.loads(serialised)
        assert len(loaded["findings"]) == 3
