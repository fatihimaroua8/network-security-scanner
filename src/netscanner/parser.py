"""Parser for Nmap XML output (-oX)."""
from __future__ import annotations

from pathlib import Path

from defusedxml import ElementTree as ET  # safe against XXE / entity bombs

from .models import Host, Port, ScanResult, Service


class NmapParseError(Exception):
    """Raised when the input is not a valid Nmap XML file."""


def _int(value: str | None, default: int = 0) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _parse_service(el) -> Service | None:
    if el is None:
        return None
    return Service(
        name=el.get("name", ""),
        product=el.get("product", ""),
        version=el.get("version", ""),
        extrainfo=el.get("extrainfo", ""),
        tunnel=el.get("tunnel", ""),
        cpes=[c.text.strip() for c in el.findall("cpe") if c.text],
    )


def _parse_port(el) -> Port:
    state = el.find("state")
    return Port(
        number=_int(el.get("portid")),
        protocol=el.get("protocol", "tcp"),
        state=state.get("state", "unknown") if state is not None else "unknown",
        reason=state.get("reason", "") if state is not None else "",
        service=_parse_service(el.find("service")),
        scripts={s.get("id", ""): s.get("output", "") for s in el.findall("script")},
    )


def _parse_host(el) -> Host:
    host = Host(address="")
    status = el.find("status")
    if status is not None:
        host.status = status.get("state", "up")

    for addr in el.findall("address"):
        atype = addr.get("addrtype", "")
        if atype in ("ipv4", "ipv6"):
            host.address, host.addr_type = addr.get("addr", ""), atype
        elif atype == "mac":
            host.mac, host.vendor = addr.get("addr", ""), addr.get("vendor", "")

    host.hostnames = [h.get("name", "") for h in el.findall("hostnames/hostname")]

    # Keep the best OS guess (Nmap lists matches by accuracy)
    matches = el.findall("os/osmatch")
    if matches:
        best = max(matches, key=lambda m: _int(m.get("accuracy")))
        host.os_name = best.get("name", "")
        host.os_accuracy = _int(best.get("accuracy"))

    host.ports = [_parse_port(p) for p in el.findall("ports/port")]
    return host


def parse_nmap_xml(source: str | Path) -> ScanResult:
    """Parse an Nmap XML file into a ScanResult."""
    try:
        root = ET.parse(str(source)).getroot()
    except ET.ParseError as exc:
        raise NmapParseError(f"Invalid XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError("Not an Nmap XML file (root element is not <nmaprun>)")

    result = ScanResult(
        nmap_version=root.get("version", ""),
        args=root.get("args", ""),
        start_time=_int(root.get("start")),
    )
    for host_el in root.findall("host"):
        host = _parse_host(host_el)
        if host.address:
            result.hosts.append(host)
    return result
