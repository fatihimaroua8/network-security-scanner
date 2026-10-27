"""Detection rules.

A rule inspects one open port of one host and returns an *evidence* string if it
matches, or None. Adding a detection = adding one Rule to RULES.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from .findings import Severity
from .models import Host, Port

Matcher = Callable[[Host, Port], Optional[str]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    match: Matcher
    references: tuple[str, ...] = ()


# --------------------------------------------------------------------------- helpers

def version_tuple(text: str) -> tuple[int, ...]:
    """'5.0.51a-3ubuntu5' -> (5, 0, 51). Empty tuple if no version found."""
    m = re.search(r"\d+(?:\.\d+)*", text or "")
    return tuple(int(x) for x in m.group().split(".")) if m else ()


def _svc_name(port: Port) -> str:
    name = (port.service.name if port.service else "").lower()
    return "" if name in ("unknown", "tcpwrapped") else name


def _is(port: Port, names: set[str], numbers: set[int] = frozenset()) -> bool:
    """True if Nmap identified one of `names`. Falls back to the port number only
    when Nmap could not identify the service (so port 3306 running HTTP is not 'MySQL')."""
    name = _svc_name(port)
    return name in names if name else port.number in numbers


def _where(port: Port) -> str:
    banner = port.service.banner if port.service else ""
    base = f"{port.number}/{port.protocol}"
    return f"{base} ({banner})" if banner else base


def _is_tls(port: Port) -> bool:
    return bool(port.service and port.service.tunnel == "ssl")


# --------------------------------------------------------------------------- matchers

def _m_telnet(host, port):
    return f"Telnet service open on {_where(port)}" if _is(port, {"telnet"}, {23}) else None


def _m_rservices(host, port):
    if _is(port, {"exec", "login", "shell"}, {512, 513, 514}):
        return f"Berkeley r-service ({_svc_name(port) or 'unidentified'}) open on {_where(port)}"


def _m_ftp_anon(host, port):
    out = port.scripts.get("ftp-anon", "")
    if "anonymous ftp login allowed" in out.lower():
        return f"NSE ftp-anon on {_where(port)}: {out.splitlines()[0]}"


def _m_ftp_cleartext(host, port):
    if _is(port, {"ftp"}, {21}) and not _is_tls(port):
        return f"FTP without TLS on {_where(port)}"


def _m_vsftpd_backdoor(host, port):
    svc = port.service
    if svc and svc.product.lower() == "vsftpd" and svc.version == "2.3.4":
        return f"vsftpd 2.3.4 detected on {_where(port)}"


def _m_smb(host, port):
    if _is(port, {"microsoft-ds", "netbios-ssn"}, {445, 139}):
        return f"SMB/NetBIOS service open on {_where(port)}"


def _m_rpc(host, port):
    if _is(port, {"msrpc"}, {135}):
        return f"Windows RPC endpoint mapper open on {_where(port)}"


def _m_rdp(host, port):
    if _is(port, {"ms-wbt-server"}, {3389}):
        return f"RDP open on {_where(port)}"


def _m_vnc(host, port):
    if _is(port, {"vnc"}, {5900}):
        return f"VNC open on {_where(port)}"


_DB_NAMES = {"mysql", "postgresql", "ms-sql-s", "oracle-tns", "oracle", "mongodb", "redis"}
_DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379}


def _m_database(host, port):
    if _is(port, _DB_NAMES, _DB_PORTS):
        return f"Database service ({_svc_name(port) or 'by port number'}) open on {_where(port)}"


# End-of-life software: (substring of Nmap product, predicate on version tuple, label)
EOL_SOFTWARE = [
    ("apache httpd", lambda v: v[:2] in ((2, 0), (2, 2)), "Apache HTTP Server 2.0/2.2 is end of life"),
    ("mysql", lambda v: v[:1] == (5,), "MySQL 5.x is end of life"),
]


def _m_eol(host, port):
    svc = port.service
    if not svc or not svc.version:
        return None
    product, ver = svc.product.lower(), version_tuple(svc.version)
    for needle, is_eol, label in EOL_SOFTWARE:
        if needle in product and ver and is_eol(ver):
            return f"{svc.banner} on {_where(port)}: {label}"


def _m_http_cleartext(host, port):
    if _is(port, {"http", "http-alt", "http-proxy"}, {80, 8080}) and not _is_tls(port):
        return f"HTTP without TLS on {_where(port)}"


# --------------------------------------------------------------------------- catalogue

RULES: list[Rule] = [
    Rule("SVC-001", "vsftpd 2.3.4 backdoor", Severity.CRITICAL,
         "This vsftpd release shipped with a backdoor that opens a root shell when a "
         "username ending in ':)' is sent.",
         "Remove or upgrade vsftpd immediately and treat the host as compromised.",
         _m_vsftpd_backdoor, ("CVE-2011-2523",)),
    Rule("SVC-002", "Telnet service exposed", Severity.HIGH,
         "Telnet transmits credentials and data in clear text.",
         "Disable Telnet and use SSH instead.",
         _m_telnet),
    Rule("SVC-003", "Berkeley r-services exposed", Severity.HIGH,
         "rexec/rlogin/rsh use weak, host-based or clear-text authentication.",
         "Disable the r-services and use SSH.",
         _m_rservices),
    Rule("FTP-001", "Anonymous FTP login allowed", Severity.HIGH,
         "Anyone can read (and possibly write) files on this FTP server without credentials.",
         "Disable anonymous access or restrict it to a read-only, non-sensitive directory.",
         _m_ftp_anon),
    Rule("FTP-002", "FTP without encryption", Severity.MEDIUM,
         "FTP sends credentials and files in clear text.",
         "Use SFTP or FTPS.",
         _m_ftp_cleartext),
    Rule("NET-001", "SMB/NetBIOS exposed", Severity.HIGH,
         "SMB is a frequent target for credential attacks and wormable vulnerabilities.",
         "Block ports 139/445 at the firewall, disable SMBv1 and restrict access to trusted hosts.",
         _m_smb),
    Rule("NET-002", "Windows RPC endpoint exposed", Severity.MEDIUM,
         "The RPC endpoint mapper reveals which services run on the host and widens the attack surface.",
         "Restrict port 135 to trusted networks.",
         _m_rpc),
    Rule("NET-003", "RDP exposed", Severity.HIGH,
         "Exposed Remote Desktop is a common entry point for brute force and ransomware.",
         "Place RDP behind a VPN, enable NLA and enforce MFA and account lockout.",
         _m_rdp),
    Rule("NET-004", "VNC exposed", Severity.HIGH,
         "VNC often uses weak passwords and weak or no encryption.",
         "Tunnel VNC through SSH or a VPN, or disable it.",
         _m_vnc),
    Rule("DB-001", "Database service exposed", Severity.HIGH,
         "A database listening on the network is reachable by attackers for brute force and exploitation.",
         "Bind the database to localhost or a private interface and filter the port.",
         _m_database),
    Rule("VER-001", "End-of-life software", Severity.MEDIUM,
         "This product version no longer receives security fixes.",
         "Upgrade to a supported release.",
         _m_eol),
    Rule("WEB-001", "HTTP without TLS", Severity.LOW,
         "Traffic is not encrypted and can be read or modified in transit.",
         "Serve the site over HTTPS and redirect HTTP to HTTPS.",
         _m_http_cleartext),
]
