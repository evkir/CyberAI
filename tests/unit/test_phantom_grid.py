from unittest.mock import patch, MagicMock
from cyberai.integrations.phantom_grid import PhantomGridClient, OOBInteraction
from cyberai.integrations.oob_payloads import (
    generate_ssrf_payloads,
    generate_xxe_payloads,
    generate_ssti_payloads,
    generate_rce_oob_payloads,
    get_all_payloads,
)


# ── phantom-grid client tests ────────────────────────────────────────


def test_client_unavailable_when_server_down():
    client = PhantomGridClient(base_url="http://127.0.0.1:19999")
    assert client.available is False


def test_new_interaction_id_unique():
    client = PhantomGridClient()
    ids = {client.new_interaction_id() for _ in range(10)}
    assert len(ids) == 10


def test_new_interaction_id_format():
    client = PhantomGridClient()
    iid = client.new_interaction_id()
    assert len(iid) == 16
    assert "-" not in iid


# Captured verbatim from a live phantom-grid v2.0 server (GET
# /api/tokens/<id>/interactions). The endpoint returns a bare JSON list.
_REAL_HTTP_ROW = {
    "body": "payload=pwn",
    "content_type": "application/x-www-form-urlencoded",
    "exfil_data": None,
    "headers": {"Host": "127.0.0.1:9090", "X-Probe": "cyberai"},
    "id": "d2120482",
    "method": "POST",
    "path": "/deep/path",
    "query": "q=1",
    "query_name": None,
    "query_type": None,
    "raw_labels": None,
    "source_ip": "127.0.0.1",
    "time": "2026-08-08T22:22:14.972748+00:00",
    "token_id": "69e0fb21d836",
    "type": "HTTP",
}


def _mock_get(mock_httpx, payload):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = payload
    mock_httpx.return_value.__enter__.return_value.get.return_value = mock_resp


@patch("cyberai.integrations.phantom_grid.httpx.Client")
def test_get_interactions_parses_real_server_row(mock_httpx):
    _mock_get(mock_httpx, [_REAL_HTTP_ROW])

    client = PhantomGridClient()
    client._available = True
    result = client.get_interactions("69e0fb21d836")

    assert len(result) == 1
    i = result[0]
    assert isinstance(i, OOBInteraction)
    # the capture token, not the row id — correlation matches on this
    assert i.interaction_id == "69e0fb21d836"
    assert i.protocol == "http"
    assert i.source_ip == "127.0.0.1"
    assert i.timestamp == "2026-08-08T22:22:14.972748+00:00"
    assert i.payload == "payload=pwn"
    assert i.data["method"] == "POST"
    assert i.data["path"] == "/deep/path"
    assert i.data["query"] == "q=1"
    assert i.data["headers"]["X-Probe"] == "cyberai"
    assert i.data["id"] == "d2120482"


@patch("cyberai.integrations.phantom_grid.httpx.Client")
def test_get_interactions_drops_null_columns_from_data(mock_httpx):
    _mock_get(mock_httpx, [_REAL_HTTP_ROW])

    client = PhantomGridClient()
    client._available = True
    data = client.get_interactions("69e0fb21d836")[0].data

    for empty in ("exfil_data", "query_name", "query_type", "raw_labels"):
        assert empty not in data


@patch("cyberai.integrations.phantom_grid.httpx.Client")
def test_get_interactions_parses_dns_row(mock_httpx):
    row = dict(_REAL_HTTP_ROW, type="DNS", body=None, query_name="tok.grid.local")
    _mock_get(mock_httpx, [row])

    client = PhantomGridClient()
    client._available = True
    i = client.get_interactions("69e0fb21d836")[0]

    assert i.protocol == "dns"
    assert i.payload == ""
    assert i.data["query_name"] == "tok.grid.local"


@patch("cyberai.integrations.phantom_grid.httpx.Client")
def test_get_interactions_rejects_non_list_body(mock_httpx):
    _mock_get(mock_httpx, {"interactions": [_REAL_HTTP_ROW]})

    client = PhantomGridClient()
    client._available = True
    # a bare [] is not enough: without the guard the dict keys would be fed to
    # _parse, raise, and be swallowed by the except into the very same [].
    with patch.object(client, "_parse") as parse:
        assert client.get_interactions("69e0fb21d836") == []
    parse.assert_not_called()


@patch("cyberai.integrations.phantom_grid.httpx.Client")
def test_get_interactions_empty_on_error(mock_httpx):
    mock_httpx.return_value.__enter__.return_value.get.side_effect = Exception("connection refused")
    client = PhantomGridClient()
    client._available = True
    result = client.get_interactions("xyz")
    assert result == []


# ── payload generator tests ──────────────────────────────────────────


def test_ssrf_payloads_count():
    payloads = generate_ssrf_payloads("grid.example.com", "abc123")
    assert len(payloads) == 4


def test_ssrf_payload_contains_interaction_id():
    iid = "deadbeef12345678"
    payloads = generate_ssrf_payloads("grid.example.com", iid)
    urls = [p["payload"] for p in payloads if iid in p["payload"]]
    assert len(urls) >= 2


def test_xxe_payloads_count():
    payloads = generate_xxe_payloads("grid.example.com", "abc123")
    assert len(payloads) == 3


def test_xxe_payload_valid_xml_structure():
    payloads = generate_xxe_payloads("grid.example.com", "abc123")
    for p in payloads:
        assert "<?xml" in p["payload"]


def test_ssti_payloads_jinja2():
    payloads = generate_ssti_payloads()
    types = [p["type"] for p in payloads]
    assert "ssti_jinja2" in types


def test_ssti_payloads_all_have_description():
    for p in generate_ssti_payloads():
        assert p.get("description")


def test_rce_payloads_contain_curl_and_wget():
    payloads = generate_rce_oob_payloads("grid.example.com", "abc123")
    types = [p["type"] for p in payloads]
    assert "rce_curl" in types
    assert "rce_wget" in types


def test_get_all_payloads_keys():
    all_p = get_all_payloads("grid.example.com", "abc123")
    assert set(all_p.keys()) == {"ssrf", "xxe", "ssti", "rce", "crlf", "sqli", "cmdi"}


def test_get_all_payloads_non_empty():
    all_p = get_all_payloads("grid.example.com", "abc123")
    for category, items in all_p.items():
        assert len(items) > 0, f"{category} payloads empty"
