from pathlib import Path

import pytest

from netscanner.cli import main
from netscanner.engine import analyze
from netscanner.findings import Finding, Severity
from netscanner.models import Host, Port, ScanResult, Service
from netscanner.parser import parse_nmap_xml
from netscanner.report import render_html

DATA = Path(__file__).parent / "data" / "sample_scan.xml"


@pytest.fixture(scope="module")
def html():
    scan = parse_nmap_xml(DATA)
    return render_html(scan, analyze(scan), scan_id=1, source="sample_scan.xml",
                       generated_at="2026-01-01 00:00 UTC")


def test_is_a_complete_html_document(html):
    assert html.startswith("<!DOCTYPE html>") and html.rstrip().endswith("</html>")


def test_contains_summary_and_findings(html):
    assert "Network Security Report" in html
    assert "vsftpd 2.3.4 backdoor" in html
    assert "192.168.56.101" in html and "metasploitable.lab" in html
    assert "Highest severity" in html and "Authorized scans only" in html
    assert "2026-01-01 00:00 UTC" in html


def test_cve_ids_link_to_nvd(html):
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2011-2523"' in html


def test_empty_scan_renders():
    out = render_html(ScanResult(), [])
    assert "No findings." in out


def test_untrusted_scan_data_is_escaped():
    """A hostile banner must not inject HTML or script into the report."""
    evil = "<script>alert(1)</script>"
    svc = Service(name="http", product=evil, version="1.0")
    scan = ScanResult(args=evil, hosts=[Host(address="10.0.0.1", hostnames=[evil],
                                             ports=[Port(80, "tcp", "open", service=svc)])])
    finding = Finding("X-1", evil, Severity.HIGH, "10.0.0.1", 80, "tcp", evil, evil, evil,
                      references=["javascript:alert(1)", "CVE-2020-0001"])
    out = render_html(scan, [finding])
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_only_wellformed_cve_ids_become_links():
    f = Finding("X-1", "t", Severity.LOW, "10.0.0.1", 80, "tcp", "e", "d", "r",
                references=["javascript:alert(1)", "CVE-2020-0001"])
    scan = ScanResult(hosts=[Host(address="10.0.0.1")])
    out = render_html(scan, [f])
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2020-0001"' in out
    assert "href=\"javascript" not in out


def test_cli_report_writes_file(tmp_path, capsys):
    dbfile, out = str(tmp_path / "t.db"), str(tmp_path / "r.html")
    main(["import", str(DATA), "--db", dbfile])
    assert main(["report", "1", "-o", out, "--db", dbfile]) == 0
    content = Path(out).read_text(encoding="utf-8")
    assert "vsftpd 2.3.4 backdoor" in content and "sample_scan.xml" in content


def test_cli_report_min_severity(tmp_path):
    dbfile, out = str(tmp_path / "t.db"), str(tmp_path / "r.html")
    main(["import", str(DATA), "--db", dbfile])
    main(["report", "1", "-o", out, "--min-severity", "critical", "--db", dbfile])
    content = Path(out).read_text(encoding="utf-8")
    assert "vsftpd 2.3.4 backdoor" in content
    assert "Telnet service exposed" not in content
