"""Unit tests for the network scanner modules."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from main import expand_target
from scanner.syn_scanner import syn_scan
from scanner.tcp_scanner import scan_port, scan_range


class TestScanner(unittest.TestCase):
    """Test cases for the scanner package."""

    def test_scan_port_grabs_banner_when_port_is_open(self) -> None:
        """scan_port should mark an open socket and return its banner."""

        mock_socket = MagicMock()
        mock_socket.__enter__.return_value = mock_socket
        mock_socket.__exit__.return_value = False
        mock_socket.connect_ex.return_value = 0
        mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        with patch("scanner.tcp_scanner.socket.socket", return_value=mock_socket):
            result = scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "open")
        self.assertIn("HTTP/1.1 200 OK", result["banner"])

    def test_syn_scan_uses_mocked_scapy_response(self) -> None:
        """syn_scan should classify a SYN-ACK response as an open port."""

        first_response = MagicMock()
        first_response.flags = 0x12

        with patch("scanner.syn_scanner.sr1", side_effect=[first_response, None]):
            state = syn_scan("127.0.0.1", 22)

        self.assertEqual(state, "open")

    def test_scan_range_returns_only_open_ports(self) -> None:
        """scan_range should filter out non-open results."""

        def fake_scan_port(host: str, port: int, timeout: float = 1.0) -> dict[str, int | str]:
            return {"port": port, "state": "open" if port % 2 == 0 else "closed", "banner": ""}

        with patch("scanner.tcp_scanner.scan_port", side_effect=fake_scan_port):
            results = scan_range("127.0.0.1", 1, 6, 1.0, 4)

        self.assertTrue(all(entry["state"] == "open" for entry in results))
        self.assertEqual([entry["port"] for entry in results], [2, 4, 6])

    def test_expand_target_parses_cidr_ranges(self) -> None:
        """expand_target should expand CIDR blocks into the expected hosts."""

        hosts = expand_target("192.168.1.0/30")

        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])


if __name__ == "__main__":
    unittest.main()