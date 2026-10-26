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
netscanner scan.xml -o inventory.json
pytest
```

## Roadmap
- [x] Step 1 – Nmap XML parser + data models
- [ ] Step 2 – SQLite inventory
- [ ] Step 3 – Rules engine & severity
- [ ] Step 4 – CVE correlation (NVD)
- [ ] Step 5 – HTML/PDF reports, scan diff
