"""Known insecure protocols and their recommended safer replacements."""

from __future__ import annotations


INSECURE_PROTOCOLS: dict[int, dict[str, str | int]] = {
	23: {
		"name": "Telnet",
		"risk": 10,
		"reason": "cleartext session",
		"replace": "SSH",
	},
	21: {
		"name": "FTP",
		"risk": 9,
		"reason": "cleartext credentials",
		"replace": "SFTP/FTPS",
	},
	512: {
		"name": "rexec",
		"risk": 10,
		"reason": "remote exec no encryption",
		"replace": "SSH",
	},
	513: {
		"name": "rlogin",
		"risk": 10,
		"reason": "remote login no encryption",
		"replace": "SSH",
	},
	80: {
		"name": "HTTP",
		"risk": 7,
		"reason": "unencrypted web traffic",
		"replace": "HTTPS port 443",
	},
	110: {
		"name": "POP3",
		"risk": 8,
		"reason": "cleartext email passwords",
		"replace": "POP3S port 995",
	},
	143: {
		"name": "IMAP",
		"risk": 8,
		"reason": "cleartext email access",
		"replace": "IMAPS port 993",
	},
	25: {
		"name": "SMTP",
		"risk": 6,
		"reason": "mail transfer no TLS",
		"replace": "SMTP+STARTTLS port 587",
	},
	161: {
		"name": "SNMP",
		"risk": 7,
		"reason": "community strings exposed",
		"replace": "SNMPv3",
	},
	69: {
		"name": "TFTP",
		"risk": 8,
		"reason": "no authentication",
		"replace": "SFTP/SCP",
	},
	389: {
		"name": "LDAP",
		"risk": 7,
		"reason": "cleartext directory data",
		"replace": "LDAPS port 636",
	},
	2049: {
		"name": "NFS",
		"risk": 6,
		"reason": "no strong auth",
		"replace": "NFSv4 with Kerberos",
	},
}
