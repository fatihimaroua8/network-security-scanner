from pathlib import Path

import pytest

from netscanner import db
from netscanner.cli import main
from netscanner.parser import parse_nmap_xml

DATA = Path(__file__).parent / "data" / "sample_scan.xml"


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    yield c
    c.close()


@pytest.fixture(scope="module")
def scan():
    return parse_nmap_xml(DATA)


def test_roundtrip_is_lossless(conn, scan):
    """What we store must come back identical."""
    scan_id = db.save_scan(conn, scan, source_file="sample_scan.xml")
    assert db.load_scan(conn, scan_id) == scan


def test_list_scans_counts(conn, scan):
    db.save_scan(conn, scan, source_file="a.xml")
    rows = db.list_scans(conn)
    assert len(rows) == 1
    assert rows[0]["hosts"] == 2
    assert rows[0]["open_ports"] == 5      # 4 on host 1 + 1 on host 2
    assert rows[0]["source_file"] == "a.xml"


def test_multiple_scans_are_independent(conn, scan):
    first = db.save_scan(conn, scan)
    second = db.save_scan(conn, scan)
    assert first != second
    assert [r["id"] for r in db.list_scans(conn)] == [second, first]  # newest first


def test_service_none_is_preserved(conn, scan):
    scan_id = db.save_scan(conn, scan)
    loaded = db.load_scan(conn, scan_id)
    closed = [p for p in loaded.hosts[0].ports if p.number == 8080][0]
    assert closed.service is None


def test_delete_cascades(conn, scan):
    scan_id = db.save_scan(conn, scan)
    db.delete_scan(conn, scan_id)
    for table in ("scans", "hosts", "ports", "scripts"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_unknown_scan(conn):
    with pytest.raises(db.ScanNotFound):
        db.load_scan(conn, 999)
    with pytest.raises(db.ScanNotFound):
        db.delete_scan(conn, 999)


def test_sql_injection_in_data_is_harmless(conn, scan):
    """Values are bound as parameters, never concatenated into SQL."""
    scan.hosts[0].hostnames = ["x'); DROP TABLE scans;--"]
    scan_id = db.save_scan(conn, scan, source_file="'; DROP TABLE hosts;--")
    assert db.load_scan(conn, scan_id).hosts[0].hostnames == ["x'); DROP TABLE scans;--"]
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_cli_import_then_show(tmp_path, capsys):
    dbfile = str(tmp_path / "t.db")
    assert main(["import", str(DATA), "--db", dbfile]) == 0
    assert main(["scans", "--db", dbfile]) == 0
    assert main(["show", "1", "--db", dbfile]) == 0
    out = capsys.readouterr().out
    assert "Scan #1 stored" in out and "vsftpd 2.3.4" in out


def test_cli_unknown_scan_returns_error(tmp_path):
    assert main(["show", "42", "--db", str(tmp_path / "t.db")]) == 1
