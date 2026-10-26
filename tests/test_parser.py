from pathlib import Path

import pytest

from netscanner.parser import NmapParseError, parse_nmap_xml

DATA = Path(__file__).parent / "data" / "sample_scan.xml"


@pytest.fixture(scope="module")
def scan():
    return parse_nmap_xml(DATA)


def test_scan_metadata(scan):
    assert scan.nmap_version == "7.94"
    assert "-sV" in scan.args
    assert len(scan.hosts) == 2


def test_host_details(scan):
    h = scan.hosts[0]
    assert h.address == "192.168.56.101"
    assert h.hostnames == ["metasploitable.lab"]
    assert h.mac == "08:00:27:AA:BB:CC"
    assert h.os_name == "Linux 2.6.9 - 2.6.33"  # best accuracy wins
    assert h.os_accuracy == 95


def test_open_ports_only(scan):
    h = scan.hosts[0]
    assert [p.number for p in h.open_ports] == [21, 23, 80, 3306]
    assert len(h.ports) == 5  # the closed port is still recorded


def test_service_and_cpe(scan):
    ftp = scan.hosts[0].ports[0]
    assert ftp.service.banner == "vsftpd 2.3.4"
    assert ftp.service.cpes == ["cpe:/a:vsftpd:vsftpd:2.3.4"]


def test_nse_scripts(scan):
    assert "Anonymous FTP" in scan.hosts[0].ports[0].scripts["ftp-anon"]


def test_host_without_optional_fields(scan):
    h = scan.hosts[1]
    assert h.hostnames == [] and h.os_name == ""
    assert h.open_ports[0].service.name == "ssh"


def test_invalid_xml(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<nmaprun><host>")
    with pytest.raises(NmapParseError):
        parse_nmap_xml(bad)


def test_wrong_root(tmp_path):
    f = tmp_path / "x.xml"
    f.write_text("<html></html>")
    with pytest.raises(NmapParseError):
        parse_nmap_xml(f)


def test_xxe_is_blocked(tmp_path):
    f = tmp_path / "xxe.xml"
    f.write_text('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                 '<nmaprun>&x;</nmaprun>')
    with pytest.raises(Exception):
        parse_nmap_xml(f)
