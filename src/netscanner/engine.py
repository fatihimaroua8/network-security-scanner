"""Rules engine: run every rule against every open port of a scan."""
from __future__ import annotations

from collections import Counter

from .findings import Finding, Severity
from .models import ScanResult
from .rules import RULES, Rule


def analyze(scan: ScanResult, rules: list[Rule] | None = None) -> list[Finding]:
    """Return findings sorted by severity (highest first), then host and port."""
    rules = RULES if rules is None else rules
    findings: list[Finding] = []
    for host in scan.hosts:
        for port in host.open_ports:          # only open ports are exposed
            for rule in rules:
                evidence = rule.match(host, port)
                if evidence:
                    findings.append(Finding(
                        rule_id=rule.id, title=rule.title, severity=rule.severity,
                        host=host.address, port=port.number, protocol=port.protocol,
                        evidence=evidence, description=rule.description,
                        recommendation=rule.recommendation,
                        references=list(rule.references),
                    ))
    findings.sort(key=lambda f: (-f.severity, f.host, f.port, f.rule_id))
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Count findings per severity name, most severe first (zeros omitted)."""
    counts = Counter(f.severity for f in findings)
    return {sev.name: counts[sev] for sev in sorted(counts, reverse=True)}
