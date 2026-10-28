from pathlib import Path

import pytest

from netscanner import db
from netscanner.correlate import correlate, severity_from_cvss
from netscanner.findings import Severity
from netscanner.nvd import CveRecord, NvdError
from netscanner.parser import parse_nmap_xml

DATA = Path(__file__).parent / "data" / "sample_scan.xml"
APACHE = "cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"
VSFTPD = "cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"


class FakeNvd:
    def __init__(self):
        self.queries = []

    def cves_for_cpe(self, cpe):
        self.queries.append(cpe)
        if cpe == APACHE:
            return [CveRecord("CVE-2017-3167", 9.8, "CRITICAL", "Auth bypass in Apache.", "2017"),
                    CveRecord("CVE-2011-3192", 5.0, "MEDIUM", "Range DoS.", "2011")]
        return [CveRecord("CVE-2011-2523", 9.8, "CRITICAL", "vsftpd backdoor.", "2011")]


class BrokenNvd:
    def cves_for_cpe(self, cpe):
        raise NvdError("cannot reach NVD")


@pytest.fixture
def scan():
    return parse_nmap_xml(DATA)


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    yield c
    c.close()


def test_severity_mapping():
    assert severity_from_cvss(9.8) is Severity.CRITICAL
    assert severity_from_cvss(9.0) is Severity.CRITICAL
    assert severity_from_cvss(7.5) is Severity.HIGH
    assert severity_from_cvss(5.0) is Severity.MEDIUM
    assert severity_from_cvss(2.0) is Severity.LOW
    assert severity_from_cvss(None) is Severity.MEDIUM


def test_findings_per_port_with_cpe(scan, conn):
    nvd = FakeNvd()
    findings, warnings = correlate(scan, nvd, conn)
    assert warnings == []
    assert sorted(nvd.queries) == sorted([APACHE, VSFTPD])     # only ports with a versioned CPE
    assert len(findings) == 2
    apache = next(f for f in findings if f.port == 80)
    assert apache.rule_id == "CVE-001" and apache.severity is Severity.CRITICAL
    assert apache.references == ["CVE-2017-3167", "CVE-2011-3192"]   # sorted by CVSS
    assert "2 CVE(s)" in apache.evidence and "9.8" in apache.evidence


def test_cache_avoids_second_lookup(scan, conn):
    nvd = FakeNvd()
    correlate(scan, nvd, conn)
    findings, _ = correlate(scan, nvd, conn)
    assert len(nvd.queries) == 2            # nothing new on the second run
    assert len(findings) == 2               # same result, served from the cache


def test_refresh_bypasses_cache(scan, conn):
    nvd = FakeNvd()
    correlate(scan, nvd, conn)
    correlate(scan, nvd, conn, refresh=True)
    assert len(nvd.queries) == 4


def test_nvd_failure_becomes_warning_not_crash(scan, conn):
    findings, warnings = correlate(scan, BrokenNvd(), conn)
    assert findings == []
    assert len(warnings) == 2 and "cannot reach NVD" in warnings[0]


def test_failures_are_not_cached(scan, conn):
    correlate(scan, BrokenNvd(), conn)
    nvd = FakeNvd()
    findings, _ = correlate(scan, nvd, conn)
    assert len(findings) == 2 and len(nvd.queries) == 2


def test_same_cpe_on_two_hosts_is_queried_once(scan, conn):
    scan.hosts[1].ports[0].service.cpes = ["cpe:/a:apache:http_server:2.2.8"]
    nvd = FakeNvd()
    correlate(scan, nvd, conn)
    assert nvd.queries.count(APACHE) == 1
