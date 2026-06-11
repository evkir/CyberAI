from unittest.mock import patch
from cyberai.agents.recon.subdomain_enum import (
    enumerate_subdomains,
    _resolve,
    load_wordlist,
    DEFAULT_WORDLIST,
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
