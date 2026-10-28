"""CVE correlation: turn Nmap CPEs into findings backed by the NVD."""
from __future__ import annotations

import sqlite3
from dataclasses import asdict
from typing import Callable

from . import db
from .cpe import usable_cpe
from .findings import Finding, Severity
from .models import ScanResult
from .nvd import CveRecord, NvdError

TOP_N = 5


def severity_from_cvss(score: float | None) -> Severity:
    """CVSS v3 qualitative scale. Unscored CVEs are treated as MEDIUM (conservative)."""
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def correlate(scan: ScanResult, client, conn: sqlite3.Connection | None = None,
              refresh: bool = False, max_age_days: int = 7,
              progress: Callable[[str], None] | None = None) -> tuple[list[Finding], list[str]]:
    """One finding per (open port, CPE) that has known CVEs.

    Returns (findings, warnings). A failed lookup becomes a warning, never a crash.
    """
    say = progress or (lambda msg: None)
    memo: dict[str, list[CveRecord] | None] = {}
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = 0

    def lookup(cpe23: str) -> list[CveRecord] | None:
        if cpe23 in memo:
            return memo[cpe23]
        if conn is not None and not refresh:
            cached = db.cache_get(conn, cpe23, max_age_days)
            if cached is not None:
                memo[cpe23] = [CveRecord(**d) for d in cached]
                return memo[cpe23]
        say(f"Querying NVD for {cpe23} ...")
        try:
            records = client.cves_for_cpe(cpe23)
        except NvdError as exc:
            warnings.append(f"{cpe23}: {exc}")
            memo[cpe23] = None
            return None
        if conn is not None:
            db.cache_put(conn, cpe23, [asdict(r) for r in records])
        memo[cpe23] = records
        return records

    for host in scan.hosts:
        for port in host.open_ports:
            cpes = []
            for raw in (port.service.cpes if port.service else []):
                cpe23 = usable_cpe(raw)
                if cpe23 and cpe23 not in cpes:
                    cpes.append(cpe23)
            if not cpes:
                skipped += 1
                continue
            for cpe23 in cpes:
                records = lookup(cpe23)
                if records:
                    findings.append(_to_finding(host.address, port, cpe23, records))

    if skipped:
        say(f"{skipped} open port(s) had no versioned CPE and were not checked.")
    return findings, warnings


def _to_finding(address: str, port, cpe23: str, records: list[CveRecord]) -> Finding:
    ranked = sorted(records, key=lambda r: (-(r.cvss if r.cvss is not None else -1), r.id))
    top = ranked[0]
    scored = [r.cvss for r in records if r.cvss is not None]
    highest = max(scored) if scored else None
    banner = port.service.banner if port.service else cpe23
    shown = ", ".join(f"{r.id} ({r.cvss if r.cvss is not None else 'n/a'})" for r in ranked[:TOP_N])
    return Finding(
        rule_id="CVE-001",
        title=f"Known vulnerabilities (CVE) for {banner}",
        severity=severity_from_cvss(highest),
        host=address, port=port.number, protocol=port.protocol,
        evidence=(f"{len(records)} CVE(s) match {cpe23}; highest CVSS "
                  f"{highest if highest is not None else 'n/a'}. Top: {shown}"),
        description=(top.description[:300] or "See the referenced CVEs on nvd.nist.gov."),
        recommendation=("Patch or upgrade the software, then verify each CVE on nvd.nist.gov. "
                        "A version match does not prove exploitability: distributions often "
                        "backport fixes without changing the version string."),
        references=[r.id for r in ranked[:10]],
    )
