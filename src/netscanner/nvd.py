"""Minimal client for the NVD CVE API 2.0 (stdlib only, rate-limit aware)."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_PAGES = 5
# NVD allows 5 requests / 30 s without an API key, 50 / 30 s with one.
INTERVAL_NO_KEY = 6.5
INTERVAL_WITH_KEY = 0.7


class NvdError(Exception):
    """Network problem, rate limiting or unexpected answer from the NVD."""


class NvdHttpError(NvdError):
    def __init__(self, status: int, message: str = ""):
        super().__init__(f"HTTP {status} {message}".strip())
        self.status = status


@dataclass
class CveRecord:
    id: str
    cvss: float | None
    severity: str
    description: str
    published: str


def _best_metric(metrics: dict) -> tuple[float | None, str]:
    """Most recent CVSS version available; NVD's own ('Primary') score first."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = entry.get("cvssData", {})
            severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
            return data.get("baseScore"), severity.upper()
    return None, ""


def parse_response(data: dict) -> list[CveRecord]:
    records = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if not cve.get("id") or cve.get("vulnStatus") == "Rejected":
            continue
        description = next((d.get("value", "") for d in cve.get("descriptions", [])
                            if d.get("lang") == "en"), "")
        score, severity = _best_metric(cve.get("metrics", {}))
        records.append(CveRecord(id=cve["id"], cvss=score, severity=severity,
                                 description=description, published=cve.get("published", "")))
    return records


def default_fetch(url: str, headers: dict, timeout: int = 30) -> dict:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raise NvdHttpError(exc.code, exc.reason) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise NvdError(f"cannot reach NVD: {exc}") from exc


class NvdClient:
    def __init__(self, api_key: str | None = None,
                 fetch: Callable[[str, dict], dict] = default_fetch,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 base_url: str = BASE_URL):
        self.api_key = api_key
        self.min_interval = INTERVAL_WITH_KEY if api_key else INTERVAL_NO_KEY
        self._fetch, self._sleep, self._clock = fetch, sleep, clock
        self._base_url = base_url
        self._last: float | None = None

    def _get(self, params: dict) -> dict:
        if self._last is not None:                       # respect the rate limit
            wait = self.min_interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()
        headers = {"User-Agent": "netscanner/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return self._fetch(f"{self._base_url}?{urllib.parse.urlencode(params)}", headers)

    def cves_for_cpe(self, cpe23: str) -> list[CveRecord]:
        """All CVEs whose applicability statements match this CPE (vulnerable only)."""
        records: list[CveRecord] = []
        start = 0
        for _ in range(MAX_PAGES):
            params = {"cpeName": cpe23, "isVulnerable": "",
                      "resultsPerPage": PAGE_SIZE, "startIndex": start}
            try:
                data = self._get(params)
            except NvdHttpError as exc:
                if exc.status == 404:                    # CPE unknown to the NVD dictionary
                    return records
                if exc.status in (403, 429):
                    raise NvdError(f"{exc} - probably rate limiting: wait 30 s "
                                   "or use an API key") from exc
                raise
            records += parse_response(data)
            returned = len(data.get("vulnerabilities", []))
            start += returned
            if returned == 0 or start >= data.get("totalResults", 0):
                break
        return records
