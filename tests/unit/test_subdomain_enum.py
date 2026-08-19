from unittest.mock import patch

from cyberai.agents.recon.subdomain_enum import (
    DEFAULT_WORDLIST,
    _resolve,
    enumerate_subdomains,
    fqdns,
    load_wordlist,
)


def test_default_wordlist_not_empty():
    assert len(DEFAULT_WORDLIST) > 10


def test_enumerate_no_results_on_fake_domain():
    with patch("cyberai.agents.recon.subdomain_enum._resolve", return_value=None):
        result = enumerate_subdomains(
            "thisdoesnotexist99999.invalid",
            wordlist=["www", "mail"],
            max_workers=2,
        )
    assert result["domain"] == "thisdoesnotexist99999.invalid"
    assert result["count"] == 0
    assert result["checked"] == 2


def test_enumerate_returns_correct_structure():
    result = enumerate_subdomains(
        "example.invalid",
        wordlist=["a", "b"],
        timeout=0.3,
    )
    assert "found" in result
    assert "count" in result
    assert "checked" in result
    assert "wordlist" in result


def test_enumerate_checked_equals_wordlist_length():
    words = ["x", "y", "z"]
    result = enumerate_subdomains("fake.invalid", wordlist=words, timeout=0.3)
    assert result["checked"] == len(words)


def test_resolve_returns_none_for_invalid():
    with patch("socket.getaddrinfo", side_effect=OSError("NXDOMAIN")):
        result = _resolve("this.absolutely.does.not.exist.invalid")
    assert result is None


def test_resolve_returns_dict_for_localhost():
    result = _resolve("localhost")
    if result:
        assert "fqdn" in result
        assert "ips" in result
        assert isinstance(result["ips"], list)


def test_enumerate_with_mock_hit():
    def mock_resolve(fqdn):
        if fqdn == "www.example.com":
            return {"fqdn": "www.example.com", "ips": ["1.2.3.4"], "subdomain": "www"}
        return None

    with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=mock_resolve):
        result = enumerate_subdomains(
            "example.com",
            wordlist=["www", "mail"],
            max_workers=2,
        )
    assert result["count"] == 1
    assert result["found"][0]["fqdn"] == "www.example.com"


def test_load_wordlist_missing_file_returns_default(tmp_path):
    result = load_wordlist(str(tmp_path / "nonexistent.txt"))
    assert result == DEFAULT_WORDLIST


def test_load_wordlist_from_file(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("sub1\nsub2\n# comment\nsub3\n")
    result = load_wordlist(str(wl))
    assert result == ["sub1", "sub2", "sub3"]


class TestFqdnsContract:
    """fqdns() is the single place that turns an enumerator result into bare
    hostnames. Both the sync ReconAgent and AsyncOrchestrator feed
    ReconResult.subdomains through it, so a shape change cannot make one
    pipeline path silently disagree with the other."""

    def test_extracts_hostnames_from_found(self):
        result = {"found": [{"fqdn": "api.t.local"}, {"fqdn": "dev.t.local"}]}
        assert fqdns(result) == ["api.t.local", "dev.t.local"]

    def test_skips_malformed_entries(self):
        result = {"found": [{"fqdn": "api.t.local"}, {"ips": ["1.2.3.4"]}, "www.t.local", {}]}
        assert fqdns(result) == ["api.t.local"]

    def test_empty_inputs_yield_empty_list(self):
        assert fqdns(None) == []
        assert fqdns({}) == []
        assert fqdns({"found": []}) == []

    def test_real_enumerator_output_is_consumable(self):
        """Guards the contract against the producer, not a hand-built dict."""
        from unittest.mock import patch

        with patch(
            "cyberai.agents.recon.subdomain_enum._resolve",
            side_effect=lambda fqdn: {"fqdn": fqdn, "ips": ["1.2.3.4"]},
        ):
            produced = enumerate_subdomains("t.local", wordlist=["api", "dev"])
        assert sorted(fqdns(produced)) == ["api.t.local", "dev.t.local"]
