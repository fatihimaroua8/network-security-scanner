from pathlib import Path

import pytest

from netscanner.cli import main
from netscanner.diff import diff_scans
from netscanner.engine import analyze
from netscanner.models import Host, ScanResult
from netscanner.parser import parse_nmap_xml

DATA = Path(__file__).parent / "data"


@pytest.fixture(scope="module")
def v1():
    return parse_nmap_xml(DATA / "sample_scan.xml")


@pytest.fixture(scope="module")
def v2():
    return parse_nmap_xml(DATA / "sample_scan_v2.xml")


@pytest.fixture(scope="module")
def d(v1, v2):
    return diff_scans(v1, v2, analyze(v1), analyze(v2))


def test_identical_scans_have_no_diff(v1):
    assert diff_scans(v1, v1, analyze(v1), analyze(v1)).is_empty


def test_hosts(d):
    assert d.new_hosts == ["192.168.56.103"]
    assert d.removed_hosts == ["192.168.56.102"]


def test_opened_and_closed_ports(d):
    assert [(p.host, p.port) for p in d.opened] == [("192.168.56.101", 8080)]
    assert [(p.host, p.port) for p in d.closed] == [("192.168.56.101", 23)]
    assert "nginx 1.25.3" in d.opened[0].label


def test_ports_of_new_or_removed_hosts_are_not_double_counted(d):
    assert all(p.port != 3389 for p in d.opened)      # covered by new_hosts
    assert all(p.port != 22 for p in d.closed)        # covered by removed_hosts


def test_service_change(d):
    assert len(d.changed) == 1
    c = d.changed[0]
    assert (c.host, c.port) == ("192.168.56.101", 80)
    assert "2.2.8" in c.old and "2.4.58" in c.new


def test_findings_diff(d):
    resolved = {(f.rule_id, f.port) for f in d.resolved_findings}
    new = {(f.rule_id, f.host, f.port) for f in d.new_findings}
    assert ("SVC-002", 23) in resolved                  # telnet closed
    assert ("VER-001", 80) in resolved                  # Apache upgraded
    assert ("VER-001", 3306) not in resolved            # MySQL 5.0 still there
    assert ("NET-003", "192.168.56.103", 3389) in new   # RDP on the new host
    assert ("WEB-001", "192.168.56.101", 8080) in new


def test_cli_diff(tmp_path, capsys):
    dbfile = str(tmp_path / "t.db")
    main(["import", str(DATA / "sample_scan.xml"), "--db", dbfile])
    main(["import", str(DATA / "sample_scan_v2.xml"), "--db", dbfile])
    capsys.readouterr()
    assert main(["diff", "1", "2", "--db", dbfile]) == 0
    out = capsys.readouterr().out
    assert "New hosts:" in out and "+ 192.168.56.103" in out
    assert "Apache httpd 2.2.8  ->  http Apache httpd 2.4.58" in out
    assert "Resolved findings:" in out


def test_cli_diff_unknown_scan(tmp_path):
    assert main(["diff", "1", "2", "--db", str(tmp_path / "t.db")]) == 1


def test_findings_of_unscanned_hosts_are_not_reported_as_resolved(v1):
    """Comparing scans of different targets must not claim that old issues were fixed."""
    other = ScanResult(hosts=[Host(address="10.9.9.9")])
    d = diff_scans(v1, other, analyze(v1), analyze(other))
    assert d.resolved_findings == []
    assert d.new_hosts == ["10.9.9.9"]
    assert set(d.removed_hosts) == {"192.168.56.101", "192.168.56.102"}
