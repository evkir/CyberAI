import asyncio
import socket
from unittest.mock import patch

import pytest

from cyberai.agents.recon.subdomain_enum import (
    DEFAULT_WORDLIST,
    _resolve,
    enumerate_subdomains,
    enumerate_subdomains_async,
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
        """Guards the contract against the producer, not a hand-built dict.

        The stub answers the wordlist and nothing else. A stub that answered
        every name would describe a wildcard zone, and the enumerator would
        correctly report no findings at all — measuring the wildcard filter
        instead of the fqdns contract this test exists for.
        """
        from unittest.mock import patch

        def resolve(fqdn):
            if fqdn.split(".")[0] in ("api", "dev"):
                return {"fqdn": fqdn, "ips": ["1.2.3.4"]}
            return None

        with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=resolve):
            produced = enumerate_subdomains("t.local", wordlist=["api", "dev"])
        assert sorted(fqdns(produced)) == ["api.t.local", "dev.t.local"]


WILDCARD_IP = "198.18.0.7"
REAL_IP = "93.184.216.34"


def _answers_everything(fqdn):
    return {"fqdn": fqdn, "ips": [WILDCARD_IP], "subdomain": fqdn.split(".")[0]}


def test_a_wildcard_zone_reports_nothing_found():
    with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=_answers_everything):
        result = enumerate_subdomains("example.com", wordlist=["www", "mail"], max_workers=2)
    assert result["wildcard"] is True
    assert result["wildcard_ips"] == [WILDCARD_IP]
    assert result["found"] == []
    assert result["count"] == 0
    assert result["checked"] == 2


def test_a_real_host_survives_a_wildcard_zone():
    def resolve(fqdn):
        if fqdn == "www.example.com":
            return {"fqdn": fqdn, "ips": [REAL_IP], "subdomain": "www"}
        return _answers_everything(fqdn)

    with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=resolve):
        result = enumerate_subdomains("example.com", wordlist=["www", "mail"], max_workers=2)
    assert [r["fqdn"] for r in result["found"]] == ["www.example.com"]


def test_a_hit_sharing_one_wildcard_address_keeps_its_own():
    def resolve(fqdn):
        if fqdn == "www.example.com":
            return {"fqdn": fqdn, "ips": [WILDCARD_IP, REAL_IP], "subdomain": "www"}
        return _answers_everything(fqdn)

    with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=resolve):
        result = enumerate_subdomains("example.com", wordlist=["www", "mail"], max_workers=2)
    assert [r["fqdn"] for r in result["found"]] == ["www.example.com"]


def test_a_clean_zone_keeps_every_hit():
    def resolve(fqdn):
        if fqdn.split(".")[0] in ("www", "mail"):
            return {"fqdn": fqdn, "ips": [REAL_IP], "subdomain": fqdn.split(".")[0]}
        return None

    with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=resolve):
        result = enumerate_subdomains("example.com", wordlist=["www", "mail"], max_workers=2)
    assert result["wildcard"] is False
    assert result["wildcard_ips"] == []
    assert result["count"] == 2


def test_one_probe_would_miss_a_rotating_wildcard():
    rotating = iter(["198.18.0.1", "198.18.0.2", "198.18.0.3"])

    def resolve(fqdn):
        if fqdn == "www.example.com":
            return {"fqdn": fqdn, "ips": ["198.18.0.3"], "subdomain": "www"}
        return {"fqdn": fqdn, "ips": [next(rotating)], "subdomain": fqdn.split(".")[0]}

    with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=resolve):
        result = enumerate_subdomains("example.com", wordlist=["www"], max_workers=1)
    assert result["found"] == []


@pytest.mark.asyncio
async def test_the_async_probe_goes_through_the_async_resolver():
    asked = []

    async def fake_resolve_async(resolver, fqdn, sem, timeout):
        asked.append(fqdn)
        return {"fqdn": fqdn, "ips": [WILDCARD_IP], "subdomain": fqdn.split(".")[0]}

    def must_not_run(fqdn):
        raise AssertionError("the async path must not resolve through getaddrinfo")

    with (
        patch("cyberai.agents.recon.subdomain_enum._resolve_async", new=fake_resolve_async),
        patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=must_not_run),
    ):
        result = await enumerate_subdomains_async("example.com", wordlist=["www"])

    assert len(asked) == 4
    assert result["wildcard"] is True
    assert result["found"] == []


def test_the_process_default_timeout_survives_a_scan():
    before = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(7.0)
        with patch("cyberai.agents.recon.subdomain_enum._resolve", return_value=None):
            enumerate_subdomains("example.com", wordlist=["www"], timeout=1.5)
        assert socket.getdefaulttimeout() == 7.0
    finally:
        socket.setdefaulttimeout(before)


def test_the_process_default_timeout_survives_a_raising_resolver():
    before = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(7.0)
        with patch(
            "cyberai.agents.recon.subdomain_enum._resolve", side_effect=RuntimeError("boom")
        ):
            with pytest.raises(RuntimeError):
                enumerate_subdomains("example.com", wordlist=["www"], timeout=1.5)
        assert socket.getdefaulttimeout() == 7.0
    finally:
        socket.setdefaulttimeout(before)


def test_the_timeout_is_in_force_while_resolving():
    """Restoring is only correct if the timeout applied in the first place."""
    seen = []

    def resolve(fqdn):
        seen.append(socket.getdefaulttimeout())
        return None

    before = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(7.0)
        with patch("cyberai.agents.recon.subdomain_enum._resolve", side_effect=resolve):
            enumerate_subdomains("example.com", wordlist=["www"], timeout=1.5)
    finally:
        socket.setdefaulttimeout(before)
    assert seen
    assert set(seen) == {1.5}


def _counting_resolver_class(state):
    """A dns.asyncresolver.Resolver that records how many queries overlap.

    The probe labels are 16 hex characters; those raise so the zone reads as
    clean and the wildcard filter leaves the hits alone.
    """

    class CountingResolver:
        async def resolve(self, fqdn, rdtype, lifetime=None):
            label = fqdn.split(".")[0]
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
            try:
                await asyncio.sleep(0.01)
            finally:
                state["current"] -= 1
            if len(label) == 16 and all(c in "0123456789abcdef" for c in label):
                raise LookupError("NXDOMAIN")
            return ["203.0.113.10"]

    return CountingResolver


@pytest.mark.asyncio
async def test_the_async_enumerator_resolves_in_parallel():
    """A serial rewrite of the gather would still pass every other test."""
    state = {"current": 0, "peak": 0}
    words = [f"w{i}" for i in range(8)]

    with patch("dns.asyncresolver.Resolver", new=_counting_resolver_class(state)):
        result = await enumerate_subdomains_async("example.com", wordlist=words, max_concurrent=4)

    assert state["peak"] == 4
    assert result["count"] == 8
    assert result["wildcard"] is False


@pytest.mark.asyncio
async def test_the_semaphore_caps_the_queries_in_flight():
    state = {"current": 0, "peak": 0}
    words = [f"w{i}" for i in range(8)]

    with patch("dns.asyncresolver.Resolver", new=_counting_resolver_class(state)):
        await enumerate_subdomains_async("example.com", wordlist=words, max_concurrent=2)

    assert state["peak"] == 2
