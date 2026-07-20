from cyberai.agents.intel.service_mapper import ports_to_queries, score_to_severity
from cyberai.agents.intel.nvd_client import _parse_cves


def test_ports_to_queries_http():
    ports = [{"port": 80, "service": "http", "state": "open"}]
    queries = ports_to_queries(ports)
    assert "nginx" in queries or "apache httpd" in queries


def test_ports_to_queries_unknown():
    ports = [{"port": 9999, "service": "unknownsvc", "state": "open"}]
    queries = ports_to_queries(ports)
    assert "unknownsvc" in queries


def test_score_to_severity():
    assert score_to_severity(9.8) == "CRITICAL"
    assert score_to_severity(7.5) == "HIGH"
    assert score_to_severity(5.0) == "MEDIUM"
    assert score_to_severity(2.0) == "LOW"


def test_parse_cves_empty():
    assert _parse_cves([]) == []


def test_parse_cves_falls_back_to_cvss_v2():
    """Legacy CVEs with only CVSS v2 metrics must still yield score+vector so
    the exploit agent renders real Vector/Complexity (regression: v2 dropped)."""
    from cyberai.agents.intel.agent import _normalize
    from cyberai.agents.exploit.cvss_analyzer import analyze_attack_vector

    vuln = {
        "cve": {
            "id": "CVE-2000-0574",
            "descriptions": [{"lang": "en", "value": "Legacy RCE"}],
            "metrics": {
                "cvssMetricV2": [
                    {
                        "baseSeverity": "HIGH",
                        "cvssData": {
                            "version": "2.0",
                            "baseScore": 7.5,
                            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        },
                    }
                ]
            },
        }
    }
    parsed = _parse_cves([vuln])[0]
    assert parsed["cvss"]["score"] == 7.5
    assert parsed["cvss"]["severity"] == "HIGH"
    assert parsed["cvss"]["vector"] == "AV:N/AC:L/Au:N/C:P/I:P/A:P"

    av = analyze_attack_vector(_normalize(parsed))
    assert av["attack_vector"] == "Network"
    assert av["attack_complexity"] == "Low"


def test_parse_cves_prefers_v3_over_v2():
    """When both v3 and v2 are present, v3 wins."""
    vuln = {
        "cve": {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "x"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N",
                        }
                    }
                ],
                "cvssMetricV2": [
                    {
                        "baseSeverity": "MEDIUM",
                        "cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N"},
                    }
                ],
            },
        }
    }
    parsed = _parse_cves([vuln])[0]
    assert parsed["cvss"]["score"] == 9.8
    assert parsed["cvss"]["severity"] == "CRITICAL"


# ── version-aware CVE relevance (severity FP reduction) ───────────────

from cyberai.agents.intel.service_mapper import product_tokens, cve_is_relevant  # noqa: E402


def test_product_tokens_from_sv_ports():
    ports = [
        {"service": "ssh", "product": "OpenSSH", "version": "6.6.1p1"},
        {"service": "http", "product": "Apache httpd", "version": "2.4.7"},
    ]
    toks = product_tokens(ports)
    assert "openssh" in toks
    assert "apache" in toks
    assert "httpd" in toks
    assert "ssh" in toks
    assert "6" not in toks and "2" not in toks


def test_product_tokens_empty_when_no_service_info():
    assert product_tokens([{"port": 80}]) == set()


def test_cve_relevant_matches_detected_product():
    toks = {"openssh", "ssh"}
    assert cve_is_relevant("OpenSSH 7.2 allows remote attackers to ...", toks)


def test_cve_irrelevant_cross_product_collision():
    """A sendmail CVE must not be considered relevant to an OpenSSH host."""
    toks = {"openssh", "ssh", "apache", "httpd"}
    desc = "Sendmail DEBUG command allows remote command execution."
    assert cve_is_relevant(desc, toks) is False


def test_cve_relevant_when_no_tokens_no_regression():
    """No product signal → cannot filter → keep prior behavior (relevant)."""
    assert cve_is_relevant("anything at all", set()) is True
