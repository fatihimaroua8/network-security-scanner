"""Command line interface.

  netscanner parse   scan.xml [-o out.json]   parse and display a scan
  netscanner import  scan.xml                 parse and store it in the inventory
  netscanner scans                            list stored scans
  netscanner show    ID                       display a stored scan
  netscanner delete  ID                       delete a stored scan
  netscanner analyze ID [--min-severity high] [--cve] [-o findings.json]
                                              security findings for a stored scan
  netscanner report  ID [-o report.html] [--cve]
                                              HTML report (print it to PDF from the browser)
  netscanner diff    OLD_ID NEW_ID            what changed between two stored scans
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import db
from .correlate import correlate
from .diff import diff_scans
from .engine import analyze, sort_findings, summarize
from .findings import Finding, Severity
from .models import ScanResult
from .nvd import NvdClient
from .parser import NmapParseError, parse_nmap_xml
from .report import render_html


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


def collect_findings(args, conn, scan: ScanResult) -> tuple[list[Finding], list[str]]:
    """Rules findings, plus NVD correlation when --cve is given; filtered by --min-severity."""
    findings, warnings = analyze(scan), []
    if args.cve:
        client = NvdClient(api_key=args.nvd_key or os.environ.get("NVD_API_KEY"))
        cve_findings, warnings = correlate(
            scan, client, conn, refresh=args.refresh,
            progress=lambda msg: print(msg, file=sys.stderr))
        findings = sort_findings(findings + cve_findings)
    threshold = Severity[args.min_severity.upper()]
    return [f for f in findings if f.severity >= threshold], warnings


def print_diff(old_id: int, new_id: int, d) -> None:
    print(f"Comparing scan #{old_id} -> scan #{new_id}\n")
    if d.is_empty:
        print("No differences.")
        return

    def section(title, lines):
        if lines:
            print(title)
            for line in lines:
                print(f"  {line}")
            print()

    section("New hosts:", [f"+ {h}" for h in d.new_hosts])
    section("Hosts no longer seen:", [f"- {h}" for h in d.removed_hosts])
    section("Newly open ports:", [f"+ {p.host}:{p.port}/{p.protocol}  {p.label}" for p in d.opened])
    section("Ports no longer open:", [f"- {p.host}:{p.port}/{p.protocol}  {p.label}" for p in d.closed])
    section("Service changes:", [f"~ {c.host}:{c.port}/{c.protocol}  {c.old}  ->  {c.new}" for c in d.changed])
    section("New findings:", [f"+ [{f.severity.name}] {f.title}  ({f.host}:{f.port}/{f.protocol})"
                              for f in d.new_findings])
    section("Resolved findings:", [f"- [{f.severity.name}] {f.title}  ({f.host}:{f.port}/{f.protocol})"
                                   for f in d.resolved_findings])


def _add_analysis_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--min-severity", choices=[s.name.lower() for s in Severity], default="info",
                   help="hide findings below this severity")
    p.add_argument("--cve", action="store_true",
                   help="correlate detected software versions with NVD CVEs (needs internet)")
    p.add_argument("--nvd-key", help="NVD API key (or set NVD_API_KEY); raises the rate limit")
    p.add_argument("--refresh", action="store_true", help="ignore the local CVE cache")


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
    _add_analysis_args(p)
    p.add_argument("-o", "--output", help="also write the findings as JSON")

    p = sub.add_parser("report", help="write an HTML report for a stored scan")
    p.add_argument("id", type=int)
    _add_analysis_args(p)
    p.add_argument("-o", "--output", help="output file (default: report_scan<ID>.html)")

    p = sub.add_parser("diff", help="compare two stored scans")
    p.add_argument("old", type=int, help="id of the older scan")
    p.add_argument("new", type=int, help="id of the newer scan")

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
            findings, warnings = collect_findings(args, conn, scan)
            counts = ", ".join(f"{n} {sev}" for sev, n in summarize(findings).items()) or "none"
            print(f"Scan #{args.id}: {len(scan.hosts)} host(s), {len(findings)} finding(s) ({counts})\n")
            print_findings(findings)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump([f.to_dict() for f in findings], fh, indent=2, ensure_ascii=False)
                print(f"JSON written to {args.output}")
            for w in warnings:
                print(f"Warning: CVE lookup failed - {w}", file=sys.stderr)

        elif args.command == "report":
            conn = db.connect(args.db)
            scan = db.load_scan(conn, args.id)
            meta = db.get_scan_meta(conn, args.id)
            findings, warnings = collect_findings(args, conn, scan)
            output = args.output or f"report_scan{args.id}.html"
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(render_html(scan, findings, scan_id=args.id, source=os.path.basename(meta["source_file"])))
            print(f"Report written to {output} ({len(findings)} finding(s))")
            for w in warnings:
                print(f"Warning: CVE lookup failed - {w}", file=sys.stderr)

        elif args.command == "diff":
            conn = db.connect(args.db)
            old, new = db.load_scan(conn, args.old), db.load_scan(conn, args.new)
            result = diff_scans(old, new, analyze(old), analyze(new))
            print_diff(args.old, args.new, result)

    except (NmapParseError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except db.ScanNotFound as exc:
        print(f"Error: scan #{exc.args[0]} not found.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
