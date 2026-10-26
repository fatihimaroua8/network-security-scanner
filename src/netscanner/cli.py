"""Command line interface.

  netscanner parse  scan.xml [-o out.json]   parse and display a scan
  netscanner import scan.xml                 parse and store it in the inventory
  netscanner scans                           list stored scans
  netscanner show   ID                       display a stored scan
  netscanner delete ID                       delete a stored scan
"""
from __future__ import annotations

import argparse
import json
import sys

from . import db
from .models import ScanResult
from .parser import NmapParseError, parse_nmap_xml


def print_scan(scan: ScanResult) -> None:
    for host in scan.hosts:
        print(f"{host.address}  ({', '.join(host.hostnames) or 'no hostname'})  {host.os_name}")
        for p in host.open_ports:
            banner = p.service.banner if p.service else ""
            name = p.service.name if p.service else "?"
            print(f"  {p.number}/{p.protocol:<4} {name:<12} {banner}")


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

    except (NmapParseError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except db.ScanNotFound as exc:
        print(f"Error: scan #{exc.args[0]} not found.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
