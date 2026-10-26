"""Minimal CLI: netscanner scan.xml [-o out.json]"""
from __future__ import annotations

import argparse
import json
import sys

from .parser import NmapParseError, parse_nmap_xml


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="netscanner",
        description="Parse Nmap XML results. Use on authorized targets only.",
    )
    ap.add_argument("xml", help="Nmap XML file (nmap -sV -oX scan.xml <target>)")
    ap.add_argument("-o", "--output", help="Write JSON inventory to this file")
    args = ap.parse_args(argv)

    try:
        scan = parse_nmap_xml(args.xml)
    except (NmapParseError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    for host in scan.hosts:
        print(f"{host.address}  ({', '.join(host.hostnames) or 'no hostname'})  {host.os_name}")
        for p in host.open_ports:
            banner = p.service.banner if p.service else ""
            name = p.service.name if p.service else "?"
            print(f"  {p.number}/{p.protocol:<4} {name:<12} {banner}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(scan.to_dict(), fh, indent=2, ensure_ascii=False)
        print(f"\nJSON written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
