"""Unit tests for the TCP/UDP scanner modules — Person A's tests.

Run with:
    python -m pytest tests/test_scanner.py -v
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import socket
import threading
import pytest

from scanner.tcp_scanner import scan_port, scan_range, grab_banner
from scanner.udp_scanner import udp_scan, udp_scan_range


# ── Helper: tiny echo server ──────────────────────────────────────────────────

class _EchoServer:
    """Spin up a real TCP server on localhost for integration tests."""

    def __init__(self, banner: bytes = b"HELLO\r\n"):
        self.banner = banner
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))  # OS assigns a free port
        self._server.listen(5)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._server.accept()
            conn.sendall(self.banner)
            conn.close()
        except Exception:
            pass

    def close(self):
        self._server.close()


# ── grab_banner ───────────────────────────────────────────────────────────────

class TestGrabBanner:
    def test_receives_banner_from_live_server(self):
        srv = _EchoServer(b"SSH-2.0-OpenSSH_9.1\r\n")
        try:
            banner = grab_banner("127.0.0.1", srv.port)
            assert "SSH" in banner
        finally:
            srv.close()

    def test_returns_empty_on_closed_port(self):
        # Find a port that's definitely closed
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        banner = grab_banner("127.0.0.1", port, timeout=0.3)
        assert banner == ""


# ── scan_port ─────────────────────────────────────────────────────────────────

class TestScanPort:
    def test_open_port_detected(self):
        srv = _EchoServer()
        try:
            result = scan_port("127.0.0.1", srv.port, timeout=2.0)
            assert result["state"] == "open"
            assert result["port"] == srv.port
        finally:
            srv.close()

    def test_closed_port_detected(self):
        # Bind then immediately close to get a free port number
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        result = scan_port("127.0.0.1", port, timeout=0.3)
        assert result["state"] == "closed"

    def test_result_contains_required_keys(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        result = scan_port("127.0.0.1", port, timeout=0.3)
        assert {"port", "state", "banner"}.issubset(result.keys())


# ── scan_range ────────────────────────────────────────────────────────────────

class TestScanRange:
    def test_finds_open_port_in_range(self):
        srv = _EchoServer()
        try:
            results = scan_range("127.0.0.1", srv.port, srv.port, timeout=2.0, max_workers=1)
            assert any(r["port"] == srv.port and r["state"] == "open" for r in results)
        finally:
            srv.close()

    def test_returns_only_open_ports(self):
        # Scan a tight range with no servers running (very high ports)
        results = scan_range("127.0.0.1", 60000, 60010, timeout=0.3, max_workers=5)
        for r in results:
            assert r["state"] == "open"

    def test_results_sorted_by_port(self):
        srv1 = _EchoServer()
        srv2 = _EchoServer()
        try:
            low  = min(srv1.port, srv2.port)
            high = max(srv1.port, srv2.port)
            results = scan_range("127.0.0.1", low, high, timeout=2.0, max_workers=5)
            ports = [r["port"] for r in results]
            assert ports == sorted(ports)
        finally:
            srv1.close()
            srv2.close()


# ── udp_scan ──────────────────────────────────────────────────────────────────

class TestUdpScan:
    def test_returns_dict_with_port_and_state(self):
        result = udp_scan("127.0.0.1", 12345, timeout=0.5)
        assert "port" in result
        assert "state" in result
        assert result["port"] == 12345

    def test_scan_range_returns_list(self):
        results = udp_scan_range("127.0.0.1", [53, 123], timeout=0.5)
        assert isinstance(results, list)
        assert len(results) == 2
