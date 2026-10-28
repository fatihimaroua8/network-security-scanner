import pytest

from netscanner.nvd import (INTERVAL_NO_KEY, INTERVAL_WITH_KEY, NvdClient, NvdError,
                            NvdHttpError, parse_response)

CPE = "cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"


def vuln(cve_id, score=None, status="Analyzed", lang="en"):
    metrics = {"cvssMetricV31": [{"type": "Primary",
                                  "cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]} if score else {}
    return {"cve": {"id": cve_id, "vulnStatus": status, "published": "2017-01-01T00:00:00.000",
                    "descriptions": [{"lang": lang, "value": f"desc {cve_id}"}], "metrics": metrics}}


class FakeTime:
    def __init__(self):
        self.now, self.slept = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def make_client(responses, api_key=None):
    t, calls = FakeTime(), []

    def fetch(url, headers):
        calls.append((url, headers))
        r = responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    return NvdClient(api_key, fetch=fetch, sleep=t.sleep, clock=t.clock), calls, t


def page(vulns, total):
    return {"resultsPerPage": 2000, "startIndex": 0, "totalResults": total, "vulnerabilities": vulns}


# ---- parsing
def test_parse_prefers_newest_cvss_and_skips_rejected():
    data = page([
        {"cve": {**vuln("CVE-1", 9.8)["cve"],
                 "metrics": {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH",
                                               "cvssData": {"baseScore": 7.5}}],
                             "cvssMetricV31": [{"type": "Primary",
                                                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}},
        vuln("CVE-2", 5.0, status="Rejected"),
        vuln("CVE-3"),                                   # no metrics yet
    ], 3)
    records = parse_response(data)
    assert [r.id for r in records] == ["CVE-1", "CVE-3"]
    assert records[0].cvss == 9.8 and records[0].severity == "CRITICAL"
    assert records[1].cvss is None
    assert records[0].description == "desc CVE-1"


def test_parse_cvss_v2_fallback_reads_severity_outside_cvssdata():
    data = page([{"cve": {"id": "CVE-9", "descriptions": [], "metrics": {
        "cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}]}}}], 1)
    r = parse_response(data)[0]
    assert (r.cvss, r.severity) == (5.0, "MEDIUM")


# ---- client
def test_request_contains_cpe_and_api_key():
    client, calls, _ = make_client([page([vuln("CVE-1", 7.5)], 1)], api_key="SECRET")
    assert [r.id for r in client.cves_for_cpe(CPE)] == ["CVE-1"]
    url, headers = calls[0]
    assert "cpeName=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.2.8" in url
    assert "isVulnerable" in url
    assert headers["apiKey"] == "SECRET"


def test_no_api_key_header_when_anonymous():
    client, calls, _ = make_client([page([], 0)])
    client.cves_for_cpe(CPE)
    assert "apiKey" not in calls[0][1]


def test_rate_limit_is_respected():
    client, _, t = make_client([page([], 0), page([], 0)])
    client.cves_for_cpe(CPE)
    assert t.slept == []                       # first call: no wait
    client.cves_for_cpe(CPE)
    assert t.slept == [pytest.approx(INTERVAL_NO_KEY)]


def test_faster_rate_with_key():
    client, _, t = make_client([page([], 0), page([], 0)], api_key="k")
    client.cves_for_cpe(CPE)
    client.cves_for_cpe(CPE)
    assert t.slept == [pytest.approx(INTERVAL_WITH_KEY)]


def test_pagination():
    client, calls, _ = make_client([page([vuln("CVE-1", 5), vuln("CVE-2", 6)], 3),
                                    page([vuln("CVE-3", 7)], 3)])
    assert [r.id for r in client.cves_for_cpe(CPE)] == ["CVE-1", "CVE-2", "CVE-3"]
    assert len(calls) == 2 and "startIndex=2" in calls[1][0]


def test_unknown_cpe_returns_empty():
    client, _, _ = make_client([NvdHttpError(404, "Not Found")])
    assert client.cves_for_cpe(CPE) == []


def test_rate_limit_error_is_explained():
    client, _, _ = make_client([NvdHttpError(403, "Forbidden")])
    with pytest.raises(NvdError, match="rate limiting"):
        client.cves_for_cpe(CPE)


def test_other_http_errors_propagate():
    client, _, _ = make_client([NvdHttpError(500, "Server Error")])
    with pytest.raises(NvdError):
        client.cves_for_cpe(CPE)
