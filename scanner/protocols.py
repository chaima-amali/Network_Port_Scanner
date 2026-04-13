"""Insecure protocol database — shared by Person A and Person B.

Each entry maps a port number to metadata used by the risk engine:
    name        : human-readable protocol name
    risk        : integer score 1–10 (CVSS-inspired)
    reason      : one-sentence explanation of the risk
    replace     : recommended secure alternative
"""

from __future__ import annotations

INSECURE_PROTOCOLS: dict[int, dict[str, str | int]] = {
    # ── CRITICAL (9–10) ──────────────────────────────────────────────────────
    23: {
        "name": "Telnet",
        "risk": 10,
        "reason": "All session data, commands, and credentials transmitted in plaintext.",
        "replace": "SSH (port 22)",
    },
    512: {
        "name": "rexec",
        "risk": 10,
        "reason": "Remote command execution with zero encryption or strong authentication.",
        "replace": "SSH (port 22)",
    },
    513: {
        "name": "rlogin",
        "risk": 10,
        "reason": "Remote login with no encryption layer whatsoever.",
        "replace": "SSH (port 22)",
    },
    21: {
        "name": "FTP",
        "risk": 9,
        "reason": "Username, password, and file contents all transmitted in plaintext.",
        "replace": "SFTP (SSH File Transfer Protocol) or FTPS",
    },
    # ── HIGH (7–8) ────────────────────────────────────────────────────────────
    110: {
        "name": "POP3",
        "risk": 8,
        "reason": "Email retrieval including passwords sent in plaintext.",
        "replace": "POP3S (port 995) with TLS",
    },
    143: {
        "name": "IMAP",
        "risk": 8,
        "reason": "Email access and credentials fully exposed in transit.",
        "replace": "IMAPS (port 993) with TLS",
    },
    69: {
        "name": "TFTP",
        "risk": 8,
        "reason": "No authentication whatsoever; any host can read or write files.",
        "replace": "SFTP or SCP",
    },
    80: {
        "name": "HTTP",
        "risk": 7,
        "reason": "All web traffic and form submissions (including passwords) unencrypted.",
        "replace": "HTTPS (port 443)",
    },
    161: {
        "name": "SNMP v1/v2c",
        "risk": 7,
        "reason": "Community strings exposed in plaintext; no message encryption.",
        "replace": "SNMPv3 with AuthPriv mode",
    },
    389: {
        "name": "LDAP",
        "risk": 7,
        "reason": "Directory data and bind credentials transmitted in plaintext.",
        "replace": "LDAPS (port 636) or LDAP+STARTTLS",
    },
    # ── MEDIUM (4–6) ──────────────────────────────────────────────────────────
    25: {
        "name": "SMTP",
        "risk": 6,
        "reason": "Mail transfer without TLS by default; credentials may be exposed.",
        "replace": "SMTP with STARTTLS (port 587) or SMTPS (port 465)",
    },
    2049: {
        "name": "NFS",
        "risk": 6,
        "reason": "File-system access without strong authentication in older versions.",
        "replace": "NFSv4 with Kerberos (krb5p)",
    },
}
