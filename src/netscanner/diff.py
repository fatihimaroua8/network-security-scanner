"""Compare two scans: what changed in exposure, and which findings appeared or disappeared."""
from __future__ import annotations

from dataclasses import dataclass, field

from .findings import Finding
from .models import Port, ScanResult


@dataclass(frozen=True)
class PortRef:
    host: str
    port: int
    protocol: str
    label: str            # e.g. "http Apache httpd 2.2.8"


@dataclass(frozen=True)
class ServiceChange:
    host: str
    port: int
    protocol: str
    old: str
    new: str


@dataclass
class ScanDiff:
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    opened: list[PortRef] = field(default_factory=list)       # newly open on a known host
    closed: list[PortRef] = field(default_factory=list)       # no longer open on a still-present host
    changed: list[ServiceChange] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not any((self.new_hosts, self.removed_hosts, self.opened, self.closed,
                        self.changed, self.new_findings, self.resolved_findings))


def _label(port: Port) -> str:
    svc = port.service
    return " ".join(x for x in ((svc.name if svc else ""), (svc.banner if svc else "")) if x) or "?"


def _index(scan: ScanResult) -> dict[tuple[str, str, int], Port]:
    return {(h.address, p.protocol, p.number): p for h in scan.hosts for p in h.open_ports}


def _finding_key(f: Finding) -> tuple:
    return (f.rule_id, f.host, f.port, f.protocol, f.title)


def diff_scans(old: ScanResult, new: ScanResult,
               old_findings: list[Finding] | None = None,
               new_findings: list[Finding] | None = None) -> ScanDiff:
    old_hosts = {h.address for h in old.hosts}
    new_hosts = {h.address for h in new.hosts}
    old_idx, new_idx = _index(old), _index(new)
    result = ScanDiff(new_hosts=sorted(new_hosts - old_hosts),
                      removed_hosts=sorted(old_hosts - new_hosts))

    # Ports of brand-new / vanished hosts are covered by new_hosts / removed_hosts.
    for (addr, proto, num), port in sorted(new_idx.items()):
        if addr in old_hosts and (addr, proto, num) not in old_idx:
            result.opened.append(PortRef(addr, num, proto, _label(port)))
    for (addr, proto, num), port in sorted(old_idx.items()):
        if addr in new_hosts and (addr, proto, num) not in new_idx:
            result.closed.append(PortRef(addr, num, proto, _label(port)))
    for key in sorted(old_idx.keys() & new_idx.keys()):
        before, after = _label(old_idx[key]), _label(new_idx[key])
        if before != after:
            result.changed.append(ServiceChange(key[0], key[2], key[1], before, after))

    if old_findings is not None and new_findings is not None:
        old_keys = {_finding_key(f) for f in old_findings}
        new_keys = {_finding_key(f) for f in new_findings}
        result.new_findings = [f for f in new_findings if _finding_key(f) not in old_keys]
        # A finding is only "resolved" if its host was scanned again: a host that is
        # absent from the new scan was not fixed, it simply was not looked at.
        result.resolved_findings = [f for f in old_findings
                                    if _finding_key(f) not in new_keys and f.host in new_hosts]
    return result
