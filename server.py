"""
demo_insecure.py — Fake Telnet + FTP servers for testing the scanner.

Run this from inside your port_scanner folder:
    python demo_insecure.py

It will:
  1. Start a fake Telnet server on port 23
  2. Start a fake FTP server on port 21
  3. Wait 1 second then launch the scanner against them
  4. Show the full Rich terminal output with CRITICAL findings
"""

import socket
import threading
import time
import subprocess
import sys


# ── Fake server factory ───────────────────────────────────────────────────────

def make_fake_server(port: int, banner: bytes, name: str) -> threading.Thread:
    """Spin up a TCP server that sends *banner* to every client that connects."""

    def _serve():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(5)
            srv.settimeout(30)          # auto-shutdown after 30 s of no activity
            print(f"[+] Fake {name} listening on port {port}")
            while True:
                try:
                    conn, addr = srv.accept()
                    conn.sendall(banner)
                    conn.close()
                except socket.timeout:
                    break
                except Exception:
                    break
            srv.close()
        except PermissionError:
            print(f"[!] Permission denied on port {port}.")
            print(f"    On Windows run as Administrator.")
            print(f"    On Linux/Mac run with: sudo python demo_insecure.py")
            sys.exit(1)
        except OSError as e:
            print(f"[!] Could not bind port {port}: {e}")
            print(f"    Another process may already be using it.")
            sys.exit(1)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Network Port Scanner — Insecure Protocol Demo")
    print("=" * 60)
    print()

    # Start fake servers
    make_fake_server(
        port=23,
        banner=b"Welcome to Telnet Service\r\nLogin: ",
        name="Telnet",
    )
    make_fake_server(
        port=21,
        banner=b"220 ProFTPD 1.3.5 Server (FakeServer) [127.0.0.1]\r\n",
        name="FTP",
    )

    # Give servers a moment to bind
    time.sleep(1)

    print()
    print("[*] Launching scanner against 127.0.0.1 ports 21-23 ...")
    print()

    # Run the scanner as a subprocess so Rich output renders properly
    result = subprocess.run(
        [sys.executable, "main.py", "-t", "127.0.0.1", "-p", "21-23"],
        cwd=".",          # must be run from inside port_scanner/
    )

    print()
    print("=" * 60)
    print("  Demo finished.")
    print("  To also generate reports run:")
    print("    python main.py -t 127.0.0.1 -p 21-23 --html report.html --output results.json")
    print("=" * 60)


if __name__ == "__main__":
    main()
    