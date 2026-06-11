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
