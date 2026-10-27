from pathlib import Path

import pytest

from netscanner.engine import analyze, summarize
from netscanner.findings import Severity
from netscanner.models import Host, Port, ScanResult, Service
from netscanner.parser import parse_nmap_xml
from netscanner.rules import RULES, version_tuple

DATA = Path(__file__).parent / "data" / "sample_scan.xml"


def make_scan(number, name="", product="", version="", state="open",
              scripts=None, tunnel="", with_service=True):
    svc = Service(name=name, product=product, version=version, tunnel=tunnel) if with_service else None
    port = Port(number=number, protocol="tcp", state=state, service=svc, scripts=scripts or {})
    return ScanResult(hosts=[Host(address="10.0.0.5", ports=[port])])


def rule_ids(scan):
    return {f.rule_id for f in analyze(scan)}


# ---- helpers
def test_version_tuple():
    assert version_tuple("5.0.51a-3ubuntu5") == (5, 0, 51)
    assert version_tuple("2.2.8") == (2, 2, 8)
    assert version_tuple("") == ()
    assert version_tuple("unknown") == ()


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


# ---- individual rules
def test_telnet():
    assert "SVC-002" in rule_ids(make_scan(23, "telnet"))


def test_ftp_anonymous():
    scan = make_scan(21, "ftp", scripts={"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"})
    assert {"FTP-001", "FTP-002"} <= rule_ids(scan)


def test_ftp_over_tls_is_not_cleartext():
    assert "FTP-002" not in rule_ids(make_scan(990, "ftp", tunnel="ssl"))


def test_vsftpd_backdoor_exact_version_only():
    assert "SVC-001" in rule_ids(make_scan(21, "ftp", "vsftpd", "2.3.4"))
    assert "SVC-001" not in rule_ids(make_scan(21, "ftp", "vsftpd", "3.0.5"))


def test_smb_and_rpc():
    assert "NET-001" in rule_ids(make_scan(445, "microsoft-ds"))
    assert "NET-002" in rule_ids(make_scan(135, "msrpc"))


def test_rdp_vnc():
    assert "NET-003" in rule_ids(make_scan(3389, "ms-wbt-server"))
    assert "NET-004" in rule_ids(make_scan(5900, "vnc"))


def test_database():
    assert "DB-001" in rule_ids(make_scan(5432, "postgresql"))


def test_port_number_fallback_only_when_service_unidentified():
    assert "DB-001" in rule_ids(make_scan(3306, with_service=False))     # unidentified -> by port
    assert "DB-001" in rule_ids(make_scan(3306, name="unknown"))
    assert "DB-001" not in rule_ids(make_scan(3306, "http", "nginx", "1.25"))  # identified as HTTP


def test_eol_software():
    assert "VER-001" in rule_ids(make_scan(80, "http", "Apache httpd", "2.2.8"))
    assert "VER-001" not in rule_ids(make_scan(80, "http", "Apache httpd", "2.4.58"))
    assert "VER-001" in rule_ids(make_scan(3306, "mysql", "MySQL", "5.0.51a-3ubuntu5"))
    assert "VER-001" not in rule_ids(make_scan(3306, "mysql", "MySQL", "8.0.36"))


def test_http_cleartext_vs_https():
    assert "WEB-001" in rule_ids(make_scan(80, "http", "nginx", "1.25"))
    assert "WEB-001" not in rule_ids(make_scan(443, "http", "nginx", "1.25", tunnel="ssl"))


def test_ssh_is_clean():
    assert analyze(make_scan(22, "ssh", "OpenSSH", "9.2p1")) == []


def test_closed_and_filtered_ports_are_ignored():
    assert analyze(make_scan(23, "telnet", state="closed")) == []
    assert analyze(make_scan(23, "telnet", state="filtered")) == []


# ---- engine on the sample scan
@pytest.fixture(scope="module")
def sample_findings():
    return analyze(parse_nmap_xml(DATA))


def test_sample_scan_summary(sample_findings):
    assert summarize(sample_findings) == {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 3, "LOW": 1}


def test_findings_sorted_by_severity(sample_findings):
    sevs = [f.severity for f in sample_findings]
    assert sevs == sorted(sevs, reverse=True)
    assert sample_findings[0].rule_id == "SVC-001"


def test_finding_to_dict_is_json_friendly(sample_findings):
    d = sample_findings[0].to_dict()
    assert d["severity"] == "CRITICAL" and d["references"] == ["CVE-2011-2523"]
