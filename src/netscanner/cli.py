"""Command line interface.

  netscanner parse  scan.xml [-o out.json]   parse and display a scan
  netscanner import scan.xml                 parse and store it in the inventory
  netscanner scans                           list stored scans
  netscanner show   ID                       display a stored scan
  netscanner delete ID                       delete a stored scan
  netscanner analyze ID [--min-severity high] [-o findings.json] [--cve]
                                             run the rules engine on a stored scan
                                             (--cve: also look up known CVEs in the NVD)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import db
from .correlate import correlate
from .engine import analyze, sort_findings, summarize
from .findings import Finding, Severity
from .models import ScanResult
from .nvd import NvdClient
from .parser import NmapParseError, parse_nmap_xml


def print_scan(scan: ScanResult) -> None:
    for host in scan.hosts:
        print(f"{host.address}  ({', '.join(host.hostnames) or 'no hostname'})  {host.os_name}")
        for p in host.open_ports:
            banner = p.service.banner if p.service else ""
            name = p.service.name if p.service else "?"
            print(f"  {p.number}/{p.protocol:<4} {name:<12} {banner}")


def print_findings(findings: list[Finding]) -> None:
    for f in findings:
        print(f"[{f.severity.name}] {f.title}  -  {f.host}:{f.port}/{f.protocol}")
        print(f"    Evidence: {f.evidence}")
        print(f"    Fix:      {f.recommendation}")
        if f.references:
            print(f"    Refs:     {', '.join(f.references)}")
        print()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="netscanner",
        description="Analyse Nmap results. Use on authorized targets only.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("parse", help="parse an Nmap XML file and display it")
    p.add_argument("xml")
    p.add_argument("-o", "--output", help="also write a JSON file")

    p = sub.add_parser("import", help="parse an Nmap XML file and store it in the database")
    p.add_argument("xml")

    sub.add_parser("scans", help="list stored scans")

    p = sub.add_parser("show", help="display a stored scan")
    p.add_argument("id", type=int)

    p = sub.add_parser("delete", help="delete a stored scan")
    p.add_argument("id", type=int)

    p = sub.add_parser("analyze", help="run the rules engine on a stored scan")
    p.add_argument("id", type=int)
    p.add_argument("--min-severity", choices=[s.name.lower() for s in Severity], default="info",
                   help="hide findings below this severity")
    p.add_argument("-o", "--output", help="also write the findings as JSON")
    p.add_argument("--cve", action="store_true",
                   help="correlate detected software versions with NVD CVEs (needs internet)")
    p.add_argument("--nvd-key", help="NVD API key (or set NVD_API_KEY); raises the rate limit")
    p.add_argument("--refresh", action="store_true", help="ignore the local CVE cache")

    for sp in sub.choices.values():
        sp.add_argument("--db", default=db.DEFAULT_DB, help=f"database file (default: {db.DEFAULT_DB})")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "parse":
            scan = parse_nmap_xml(args.xml)
            print_scan(scan)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump(scan.to_dict(), fh, indent=2, ensure_ascii=False)
                print(f"\nJSON written to {args.output}")

        elif args.command == "import":
            scan = parse_nmap_xml(args.xml)
            conn = db.connect(args.db)
            scan_id = db.save_scan(conn, scan, source_file=args.xml)
            n_ports = sum(len(h.open_ports) for h in scan.hosts)
            print(f"Scan #{scan_id} stored: {len(scan.hosts)} host(s), {n_ports} open port(s) -> {args.db}")

        elif args.command == "scans":
            rows = db.list_scans(db.connect(args.db))
            if not rows:
                print("No scans stored yet. Use: netscanner import scan.xml")
            for r in rows:
                print(f"#{r['id']:<3} {r['imported_at']}  {r['hosts']} host(s)  "
                      f"{r['open_ports']} open port(s)  {r['source_file']}")

        elif args.command == "show":
            print_scan(db.load_scan(db.connect(args.db), args.id))

        elif args.command == "delete":
            db.delete_scan(db.connect(args.db), args.id)
            print(f"Scan #{args.id} deleted.")

        elif args.command == "analyze":
            conn = db.connect(args.db)
            scan = db.load_scan(conn, args.id)
            threshold = Severity[args.min_severity.upper()]
            findings, warnings = analyze(scan), []
            if args.cve:
                client = NvdClient(api_key=args.nvd_key or os.environ.get("NVD_API_KEY"))
                cve_findings, warnings = correlate(
                    scan, client, conn, refresh=args.refresh,
                    progress=lambda msg: print(msg, file=sys.stderr))
                findings = sort_findings(findings + cve_findings)
            findings = [f for f in findings if f.severity >= threshold]
            counts = ", ".join(f"{n} {sev}" for sev, n in summarize(findings).items()) or "none"
            print(f"Scan #{args.id}: {len(scan.hosts)} host(s), {len(findings)} finding(s) ({counts})\n")
            print_findings(findings)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump([f.to_dict() for f in findings], fh, indent=2, ensure_ascii=False)
                print(f"JSON written to {args.output}")
            for w in warnings:
                print(f"Warning: CVE lookup failed - {w}", file=sys.stderr)

    except (NmapParseError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except db.ScanNotFound as exc:
        print(f"Error: scan #{exc.args[0]} not found.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
