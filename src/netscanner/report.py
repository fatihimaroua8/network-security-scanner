"""HTML report generation (Jinja2 with autoescaping: scan data is untrusted input)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from jinja2 import Environment

from .findings import Finding, Severity
from .models import ScanResult

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Security Report{% if scan_id %} - scan #{{ scan_id }}{% endif %}</title>
<style>
  :root { --fg:#1f2937; --muted:#6b7280; --line:#e5e7eb; --bg:#ffffff; --card:#f9fafb;
          --critical:#7f1d1d; --high:#c2410c; --medium:#b45309; --low:#1d4ed8; --info:#4b5563; }
  * { box-sizing: border-box; }
  body { font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color: var(--fg);
         background: var(--bg); max-width: 960px; margin: 0 auto; padding: 32px 20px; }
  h1 { margin: 0 0 4px; font-size: 26px; } h2 { margin-top: 36px; border-bottom: 2px solid var(--line); padding-bottom: 6px; }
  h3 { margin: 24px 0 8px; } code { background: var(--card); padding: 1px 5px; border-radius: 4px; word-break: break-all; }
  .meta { color: var(--muted); margin: 2px 0; }
  .notice { background: #fffbeb; border: 1px solid #fcd34d; padding: 10px 14px; border-radius: 6px; margin: 18px 0; }
  .cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0; }
  .card { flex: 1 1 110px; background: var(--card); border: 1px solid var(--line); border-radius: 8px;
          padding: 12px; text-align: center; }
  .card .n { font-size: 28px; font-weight: 700; } .card .l { color: var(--muted); font-size: 12px; text-transform: uppercase; }
  .card.critical .n { color: var(--critical); } .card.high .n { color: var(--high); }
  .card.medium .n { color: var(--medium); } .card.low .n { color: var(--low); }
  table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); font-size: 14px; }
  th { background: var(--card); }
  .badge { display: inline-block; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; }
  .badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
  .badge.medium { background: var(--medium); } .badge.low { background: var(--low); } .badge.info { background: var(--info); }
  .finding { border: 1px solid var(--line); border-left-width: 5px; border-radius: 6px; padding: 10px 14px; margin: 10px 0; page-break-inside: avoid; }
  .finding.critical { border-left-color: var(--critical); } .finding.high { border-left-color: var(--high); }
  .finding.medium { border-left-color: var(--medium); } .finding.low { border-left-color: var(--low); }
  .finding.info { border-left-color: var(--info); } .finding p { margin: 4px 0; }
  .where { color: var(--muted); font-size: 13px; margin-left: 6px; }
  .host { page-break-before: auto; } footer { margin-top: 40px; color: var(--muted); font-size: 12px; }
  @media print { body { max-width: none; padding: 0; } .host { page-break-inside: avoid; } }
</style>
</head>
<body>
<header>
  <h1>Network Security Report</h1>
  <p class="meta">{% if scan_id %}Scan #{{ scan_id }} &middot; {% endif %}{% if source %}Source: {{ source }} &middot; {% endif %}Nmap {{ scan.nmap_version or "?" }} &middot; Scanned: {{ scan_date }}</p>
  {% if scan.args %}<p class="meta">Command: <code>{{ scan.args }}</code></p>{% endif %}
</header>

<p class="notice"><strong>Authorized scans only.</strong> This report describes exposure observed during a scan of systems the author is authorized to test.
Findings are indicators to verify, not proof of exploitability.</p>

<section>
  <h2>Executive summary</h2>
  <div class="cards">
    <div class="card"><div class="n">{{ scan.hosts|length }}</div><div class="l">Hosts</div></div>
    <div class="card"><div class="n">{{ open_ports }}</div><div class="l">Open ports</div></div>
    {% for name, n in counts %}
    <div class="card {{ name|lower }}"><div class="n">{{ n }}</div><div class="l">{{ name }}</div></div>
    {% endfor %}
  </div>
  {% if findings %}
    <p>{{ findings|length }} finding(s). Highest severity: <span class="badge {{ top_severity|lower }}">{{ top_severity }}</span></p>
    {% if priority %}
    <h3>Priority issues</h3>
    <ul>
      {% for f in priority %}<li><span class="badge {{ f.severity|lower }}">{{ f.severity }}</span> {{ f.title }} <span class="where">{{ f.host }}:{{ f.port }}/{{ f.protocol }}</span></li>{% endfor %}
    </ul>
    {% endif %}
  {% else %}
    <p>No findings.</p>
  {% endif %}
</section>

<section>
  <h2>Hosts</h2>
  {% for h in hosts %}
  <div class="host">
    <h3>{{ h.address }}{% if h.hostnames %} <span class="where">{{ h.hostnames|join(", ") }}</span>{% endif %}</h3>
    <p class="meta">{% if h.os_name %}OS guess: {{ h.os_name }} ({{ h.os_accuracy }}%){% else %}OS: unknown{% endif %}{% if h.mac %} &middot; MAC {{ h.mac }}{% if h.vendor %} ({{ h.vendor }}){% endif %}{% endif %}</p>

    {% if h.ports %}
    <table>
      <tr><th>Port</th><th>Service</th><th>Product / version</th></tr>
      {% for p in h.ports %}<tr><td>{{ p.number }}/{{ p.protocol }}</td><td>{{ p.name }}</td><td>{{ p.banner }}</td></tr>{% endfor %}
    </table>
    {% else %}<p>No open ports.</p>{% endif %}

    {% for f in h.findings %}
    <div class="finding {{ f.severity|lower }}">
      <div><span class="badge {{ f.severity|lower }}">{{ f.severity }}</span> <strong>{{ f.title }}</strong><span class="where">{{ f.port }}/{{ f.protocol }}</span></div>
      <p><strong>Evidence:</strong> {{ f.evidence }}</p>
      <p><strong>Why it matters:</strong> {{ f.description }}</p>
      <p><strong>Recommendation:</strong> {{ f.recommendation }}</p>
      {% if f.refs %}<p><strong>References:</strong>
        {% for r in f.refs %}{% if r.url %}<a href="{{ r.url }}">{{ r.id }}</a>{% else %}{{ r.id }}{% endif %}{% if not loop.last %}, {% endif %}{% endfor %}</p>{% endif %}
    </div>
    {% endfor %}
  </div>
  {% endfor %}
</section>

<footer>Generated {{ generated_at }} by netscanner.</footer>
</body>
</html>
"""

_env = Environment(autoescape=True)      # escape everything: banners come from the network
_template = _env.from_string(TEMPLATE)


def _refs(finding: Finding) -> list[dict]:
    """Only well-formed CVE ids become links; anything else stays plain (escaped) text."""
    return [{"id": r, "url": f"https://nvd.nist.gov/vuln/detail/{r}" if _CVE_ID.match(r) else None}
            for r in finding.references]


def _view(f: Finding) -> dict:
    return {"severity": f.severity.name, "title": f.title, "host": f.host, "port": f.port,
            "protocol": f.protocol, "evidence": f.evidence, "description": f.description,
            "recommendation": f.recommendation, "refs": _refs(f)}


def render_html(scan: ScanResult, findings: list[Finding], scan_id: int | None = None,
                source: str = "", generated_at: str | None = None) -> str:
    views = [_view(f) for f in findings]
    hosts = []
    for h in scan.hosts:
        hosts.append({
            "address": h.address, "hostnames": h.hostnames, "os_name": h.os_name,
            "os_accuracy": h.os_accuracy, "mac": h.mac, "vendor": h.vendor,
            "ports": [{"number": p.number, "protocol": p.protocol,
                       "name": p.service.name if p.service else "?",
                       "banner": " ".join(x for x in (p.service.banner, p.service.extrainfo) if x)
                       if p.service else ""} for p in h.open_ports],
            "findings": [v for v in views if v["host"] == h.address],
        })
    by_sev = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    counts = [(s.name, by_sev[s]) for s in sorted(Severity, reverse=True)]
    top = max((f.severity for f in findings), default=None)
    scan_date = (datetime.fromtimestamp(scan.start_time, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                 if scan.start_time else "unknown")
    return _template.render(
        scan=scan, scan_id=scan_id, source=source, scan_date=scan_date,
        generated_at=generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        open_ports=sum(len(h.open_ports) for h in scan.hosts),
        findings=views, counts=counts, top_severity=top.name if top is not None else "",
        priority=[v for v in views if v["severity"] in ("CRITICAL", "HIGH")][:5], hosts=hosts)
