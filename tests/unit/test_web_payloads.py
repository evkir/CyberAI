"""Tests for the direct web-exploitation payload corpus."""

from __future__ import annotations

import pytest

from cyberai.agents.exploit.web_payloads import (
    WebVulnClass,
    full_corpus,
    payloads_for,
    verify_corpus_is_non_reflective,
)


def test_every_class_has_payloads():
    for vc in WebVulnClass:
        assert payloads_for(vc), f"no payloads for {vc.value}"


def test_no_payload_is_confirmed_by_its_own_text():
    """The corpus-wide invariant: reflection can never prove exploitation."""
    assert verify_corpus_is_non_reflective() == []


def test_reflection_of_any_payload_never_proves_a_solve():
    """Simulate a target that echoes the request verbatim in a 404 body."""
    for p in full_corpus():
        echoed = f"404 not found: {p.value}"
        assert p.proof.holds(echoed) is False, f"{p.vuln_class.value}: {p.value!r} faked by echo"


def test_cmdi_proof_needs_the_product_not_the_expression():
    payload = payloads_for(WebVulnClass.COMMAND_INJECTION)[0]
    assert payload.proof.holds("PING 127.0.0.1\n20571\n") is True
    assert payload.proof.holds("PING 127.0.0.1\n$((6857*3))\n") is False


def test_traversal_proof_needs_file_contents():
    passwd_payload = payloads_for(WebVulnClass.PATH_TRAVERSAL)[0]
    assert passwd_payload.proof.holds("root:x:0:0:root:/root:/bin/bash\n") is True
    assert passwd_payload.proof.holds("404 not found: ../../etc/passwd") is False


PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


def test_every_traversal_payload_is_proven_by_the_file_it_reads():
    """No traversal payload may depend on knowing what a specific target holds.

    A proof naming a constant our own bench app plants is confirmed only by
    that app: against any other host the payload lands and the corpus reports
    nothing. The shape of /etc/passwd is the opposite -- present on every Linux
    target, absent from the request -- which is what makes it evidence rather
    than recognition.
    """
    for p in payloads_for(WebVulnClass.PATH_TRAVERSAL):
        assert p.proof.holds(PASSWD_BODY) is True, f"{p.value!r} cannot be proven off-bench"


def test_sqli_proof_needs_an_authenticated_response():
    payload = [p for p in payloads_for(WebVulnClass.SQLI) if "error-based" not in p.tags][0]
    assert payload.proof.holds('{"status": "ok", "flag": "FLAG{x}"}') is True
    assert payload.proof.holds('{"status": "denied"}') is False


def test_every_payload_carries_a_human_readable_proof():
    for p in full_corpus():
        assert p.proof.description.strip(), f"{p.value!r} has no evidence description"


def test_verifier_catches_a_deliberately_unsafe_payload():
    """The guard must actually fire, not just pass on a clean corpus."""
    from cyberai.agents.exploit.web_payloads import Proof, WebPayload

    unsafe = WebPayload(
        vuln_class=WebVulnClass.SQLI,
        value="' OR MARKER123 -- ",
        proof=Proof(description="marker echoed", expected="MARKER123"),
    )
    assert verify_corpus_is_non_reflective([unsafe]) != []


def _error_based():
    return [p for p in payloads_for(WebVulnClass.SQLI) if "error-based" in p.tags]


def test_error_based_payloads_exist_and_are_minimal():
    payloads = _error_based()
    assert payloads
    assert {p.value for p in payloads} == {"'", '"'}


def test_error_based_proof_reads_an_engine_parse_error():
    proof = _error_based()[0].proof
    body = "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token"
    assert proof.holds(body) is True


def test_error_based_proof_recognises_other_engines():
    proof = _error_based()[0].proof
    assert proof.holds("You have an error in your SQL syntax; MySQL server version") is True
    assert proof.holds("ORA-01756: quoted string not properly terminated") is True


def test_error_based_proof_ignores_a_generic_server_error():
    """A 500 that is not a database complaint proves nothing about SQL."""
    proof = _error_based()[0].proof
    assert proof.holds("500 Internal Server Error") is False
    assert proof.holds("TypeError: cannot read property of undefined") is False


def test_error_based_proof_states_what_it_does_not_prove():
    """The description must not read as data extraction."""
    description = _error_based()[0].proof.description
    assert "reached the query" in description


ENGINE_ERRORS = [
    ("node-sqlite3", "Error: SQLITE_ERROR: near \"'%'\": syntax error"),
    ("mysql", "ER_PARSE_ERROR: You have an error in your SQL syntax"),
    ("postgres", 'syntax error at or near "\'"'),
    ("sequelize", 'SequelizeDatabaseError: near "\'": syntax error'),
    ("mssql", "System.Data.SqlClient.SqlException: Incorrect syntax"),
]


@pytest.mark.parametrize("stack,body", ENGINE_ERRORS)
def test_error_proof_reads_every_stack_we_know(stack, body):
    """One fault, worded per driver: a corpus fluent in one stack is blind to the rest."""
    proof = _error_based()[0].proof
    assert proof.holds(body) is True, stack


NON_DATABASE_BODIES = [
    '{"status":"success","data":[]}',
    "404 Not Found",
    "TypeError: cannot read property of undefined",
    "Error: connection refused",
    "500 Internal Server Error",
]


@pytest.mark.parametrize("body", NON_DATABASE_BODIES)
def test_error_proof_ignores_failures_that_are_not_the_database(body):
    """A server that broke for another reason is not evidence of injection."""
    assert _error_based()[0].proof.holds(body) is False


def test_open_source_is_not_a_remote_code_execution():
    from cyberai.agents.exploit.web_payloads import classes_from_description

    # "rce" sits inside "source" in ten of the forty upstream descriptions.
    order = classes_from_description("An open-source tool with a SQL injection flaw.")

    assert order[0] is WebVulnClass.SQLI


def test_a_consequence_does_not_outrank_the_vulnerability():
    from cyberai.agents.exploit.web_payloads import classes_from_description

    # Upstream states the class first and what it enables last. Read as a set,
    # this description names two classes; read in order, it names traversal.
    order = classes_from_description(
        "The plugin is vulnerable to arbitrary file deletion, which can make "
        "site takeover and remote code execution possible."
    )

    assert order[0] is WebVulnClass.PATH_TRAVERSAL
    assert order[1] is WebVulnClass.COMMAND_INJECTION


def test_no_class_is_ever_dropped():
    from cyberai.agents.exploit.web_payloads import classes_from_description

    # The caller narrows a pool with this, and the exploit loop gives an inert
    # parameter one class only. A dropped class is a lost finding, not a
    # reordering, so every description returns the whole enum.
    for text in ("", "sql injection", "an XML External Entity (XXE) flaw"):
        assert sorted(classes_from_description(text), key=lambda c: c.value) == sorted(
            WebVulnClass, key=lambda c: c.value
        ), text


def test_an_unrecognised_description_keeps_the_default_order():
    from cyberai.agents.exploit.web_payloads import classes_from_description

    assert classes_from_description("Improper Privilege Management in a plugin.") == list(
        WebVulnClass
    )
