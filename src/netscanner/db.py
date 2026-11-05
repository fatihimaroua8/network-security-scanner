"""SQLite inventory: persist scans, hosts, ports, services and NSE script output."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import Host, Port, ScanResult, Service

DEFAULT_DB = "netscanner.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file   TEXT,
    nmap_version  TEXT,
    args          TEXT,
    start_time    INTEGER,
    imported_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    addr_type    TEXT,
    status       TEXT,
    hostnames    TEXT,           -- JSON list
    mac          TEXT,
    vendor       TEXT,
    os_name      TEXT,
    os_accuracy  INTEGER
);

CREATE TABLE IF NOT EXISTS ports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    number        INTEGER NOT NULL,
    protocol      TEXT NOT NULL,
    state         TEXT NOT NULL,
    reason        TEXT,
    svc_name      TEXT,          -- NULL when Nmap reported no <service>
    svc_product   TEXT,
    svc_version   TEXT,
    svc_extrainfo TEXT,
    svc_tunnel    TEXT,
    svc_cpes      TEXT           -- JSON list
);

CREATE TABLE IF NOT EXISTS scripts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id    INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    script_id  TEXT NOT NULL,
    output     TEXT
);

CREATE TABLE IF NOT EXISTS cve_cache (
    cpe         TEXT PRIMARY KEY,   -- CPE 2.3 string used for the NVD lookup
    fetched_at  TEXT NOT NULL,
    payload     TEXT NOT NULL       -- JSON list of CVE records
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan   ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_host   ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_scripts_port ON scripts(port_id);
"""


class ScanNotFound(KeyError):
    """Raised when a scan id does not exist in the database."""


def connect(path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    """Open (and initialise) the inventory database. Use ':memory:' for tests."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # off by default in SQLite!
    conn.executescript(SCHEMA)
    return conn


def save_scan(conn: sqlite3.Connection, scan: ScanResult, source_file: str = "") -> int:
    """Store a whole scan in one transaction. Returns the new scan id."""
    with conn:  # commit on success, rollback on error
        cur = conn.execute(
            "INSERT INTO scans (source_file, nmap_version, args, start_time, imported_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (source_file, scan.nmap_version, scan.args, scan.start_time,
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        scan_id = cur.lastrowid

        for host in scan.hosts:
            hcur = conn.execute(
                "INSERT INTO hosts (scan_id, address, addr_type, status, hostnames,"
                " mac, vendor, os_name, os_accuracy) VALUES (?,?,?,?,?,?,?,?,?)",
                (scan_id, host.address, host.addr_type, host.status,
                 json.dumps(host.hostnames), host.mac, host.vendor,
                 host.os_name, host.os_accuracy),
            )
            host_id = hcur.lastrowid

            for port in host.ports:
                svc = port.service
                pcur = conn.execute(
                    "INSERT INTO ports (host_id, number, protocol, state, reason,"
                    " svc_name, svc_product, svc_version, svc_extrainfo, svc_tunnel, svc_cpes)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (host_id, port.number, port.protocol, port.state, port.reason,
                     svc.name if svc else None,
                     svc.product if svc else None,
                     svc.version if svc else None,
                     svc.extrainfo if svc else None,
                     svc.tunnel if svc else None,
                     json.dumps(svc.cpes) if svc else None),
                )
                port_id = pcur.lastrowid
                conn.executemany(
                    "INSERT INTO scripts (port_id, script_id, output) VALUES (?,?,?)",
                    [(port_id, sid, out) for sid, out in port.scripts.items()],
                )
    return scan_id


def list_scans(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """All scans, newest first, with host and open-port counts."""
    return conn.execute(
        """
        SELECT s.id, s.source_file, s.imported_at,
               COUNT(DISTINCT h.id)                          AS hosts,
               COUNT(CASE WHEN p.state = 'open' THEN 1 END)  AS open_ports
        FROM scans s
        LEFT JOIN hosts h ON h.scan_id = s.id
        LEFT JOIN ports p ON p.host_id = h.id
        GROUP BY s.id
        ORDER BY s.id DESC
        """
    ).fetchall()


def load_scan(conn: sqlite3.Connection, scan_id: int) -> ScanResult:
    """Rebuild a ScanResult (same objects the parser produces) from the database."""
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise ScanNotFound(scan_id)

    scan = ScanResult(nmap_version=row["nmap_version"] or "", args=row["args"] or "",
                      start_time=row["start_time"] or 0)

    for h in conn.execute("SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)):
        host = Host(
            address=h["address"], addr_type=h["addr_type"] or "ipv4",
            status=h["status"] or "up", hostnames=json.loads(h["hostnames"] or "[]"),
            mac=h["mac"] or "", vendor=h["vendor"] or "",
            os_name=h["os_name"] or "", os_accuracy=h["os_accuracy"] or 0,
        )
        for p in conn.execute("SELECT * FROM ports WHERE host_id = ? ORDER BY id", (h["id"],)):
            service = None
            if p["svc_name"] is not None:
                service = Service(
                    name=p["svc_name"], product=p["svc_product"] or "",
                    version=p["svc_version"] or "", extrainfo=p["svc_extrainfo"] or "",
                    tunnel=p["svc_tunnel"] or "", cpes=json.loads(p["svc_cpes"] or "[]"),
                )
            scripts = {
                s["script_id"]: s["output"] or ""
                for s in conn.execute("SELECT script_id, output FROM scripts WHERE port_id = ?",
                                      (p["id"],))
            }
            host.ports.append(Port(number=p["number"], protocol=p["protocol"],
                                   state=p["state"], reason=p["reason"] or "",
                                   service=service, scripts=scripts))
        scan.hosts.append(host)
    return scan


def delete_scan(conn: sqlite3.Connection, scan_id: int) -> None:
    """Delete a scan and (via ON DELETE CASCADE) all its hosts, ports and scripts."""
    with conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    if cur.rowcount == 0:
        raise ScanNotFound(scan_id)


def cache_get(conn: sqlite3.Connection, cpe: str, max_age_days: int = 7) -> list[dict] | None:
    """Cached NVD answer for a CPE, or None if absent or older than max_age_days."""
    row = conn.execute("SELECT fetched_at, payload FROM cve_cache WHERE cpe = ?", (cpe,)).fetchone()
    if row is None:
        return None
    age = datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"])
    if age > timedelta(days=max_age_days):
        return None
    return json.loads(row["payload"])


def cache_put(conn: sqlite3.Connection, cpe: str, records: list[dict]) -> None:
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (cpe, fetched_at, payload) VALUES (?, ?, ?)",
            (cpe, datetime.now(timezone.utc).isoformat(timespec="seconds"), json.dumps(records)),
        )


def get_scan_meta(conn: sqlite3.Connection, scan_id: int) -> dict:
    """source_file and imported_at of a stored scan."""
    row = conn.execute("SELECT source_file, imported_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise ScanNotFound(scan_id)
    return {"source_file": row["source_file"] or "", "imported_at": row["imported_at"]}
