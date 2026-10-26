"""Data models: a normalized, tool-independent view of an Nmap scan."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Service:
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""          # e.g. "ssl"
    cpes: list[str] = field(default_factory=list)

    @property
    def banner(self) -> str:
        """Human-readable 'product version' string."""
        return " ".join(p for p in (self.product, self.version) if p)


@dataclass
class Port:
    number: int
    protocol: str             # tcp / udp
    state: str                # open / closed / filtered ...
    reason: str = ""
    service: Optional[Service] = None
    scripts: dict[str, str] = field(default_factory=dict)  # NSE id -> output

    @property
    def is_open(self) -> bool:
        return self.state == "open"


@dataclass
class Host:
    address: str
    addr_type: str = "ipv4"
    status: str = "up"
    hostnames: list[str] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    os_name: str = ""
    os_accuracy: int = 0
    ports: list[Port] = field(default_factory=list)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.is_open]


@dataclass
class ScanResult:
    nmap_version: str = ""
    args: str = ""
    start_time: int = 0       # unix timestamp
    hosts: list[Host] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
