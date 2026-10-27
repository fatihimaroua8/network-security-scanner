"""Security findings: what the rules engine produces."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that higher means more severe (sorting and filtering are trivial)."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    host: str
    port: int
    protocol: str
    evidence: str
    description: str
    recommendation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "evidence": self.evidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "references": list(self.references),
        }
