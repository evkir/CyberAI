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


@patch("cyberai.integrations.phantom_grid.httpx.Client")
def test_get_interactions_returns_parsed(mock_httpx):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "interactions": [
            {
                "id": "abc123",
                "protocol": "dns",
                "source_ip": "1.2.3.4",
                "timestamp": "2024-01-01T00:00:00",
                "payload": "test",
                "data": {},
            }
        ]
    }
    mock_httpx.return_value.__enter__.return_value.get.return_value = mock_resp

    client = PhantomGridClient()
    client._available = True
    result = client.get_interactions("abc123")

    assert len(result) == 1
    assert isinstance(result[0], OOBInteraction)
    assert result[0].protocol == "dns"
    assert result[0].source_ip == "1.2.3.4"


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
    assert set(all_p.keys()) == {"ssrf", "xxe", "ssti", "rce"}


def test_get_all_payloads_non_empty():
    all_p = get_all_payloads("grid.example.com", "abc123")
    for category, items in all_p.items():
        assert len(items) > 0, f"{category} payloads empty"
