# netscanner

Parse **authorized** Nmap scan results, inventory exposed services and produce structured security findings.

> ⚠️ **Authorized scans only.** Run Nmap exclusively against systems you own or have written permission to test
> (e.g. your own lab VMs, `scanme.nmap.org`).

## Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage
```bash
nmap -sV -O -oX scan.xml 192.168.56.101     # lab target you own
netscanner parse scan.xml -o inventory.json   # display + JSON export
netscanner import scan.xml                    # store in SQLite (netscanner.db)
netscanner scans                              # list stored scans
netscanner show 1                             # display stored scan #1
netscanner analyze 1 --min-severity medium    # security findings
netscanner analyze 1 --cve                    # + known CVEs from the NVD (internet)
pytest
```

## Roadmap
- [x] Step 1 – Nmap XML parser + data models
- [x] Step 2 – SQLite inventory
- [x] Step 3 – Rules engine & severity
- [x] Step 4 – CVE correlation (NVD)
- [ ] Step 5 – HTML/PDF reports, scan diff

## Limitations
- CVE matching is **version-based**: it can report CVEs already fixed by a distribution backport (false positives)
  and miss software Nmap could not identify (false negatives).
- Only services for which Nmap reports a versioned application CPE are checked.
- Nmap CPE vendor/product names do not always match the NVD dictionary; unknown CPEs return no CVE.
