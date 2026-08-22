"""The web exploitation path asks the model, and asks it about the report."""

from unittest.mock import MagicMock


def _web_agent(llm):
    from cyberai.agents.exploit.agent import ExploitAgent

    agent = ExploitAgent.__new__(ExploitAgent)
    agent.AGENT_NAME = "exploit"
    agent.llm = llm
    agent.config = MagicMock()
    return agent


REPORT = {
    "confirmed": 1,
    "endpoints_tested": 14,
    "findings": [
        {
            "vuln_class": "sqli",
            "url": "http://127.0.0.1:3000/rest/products/search",
            "parameter": "q",
            "payload": "apple'",
            "proof": "SQLITE_ERROR near syntax",
        }
    ],
    "inert_params": ["limit"],
    "unauthorized_params": ["token"],
}


def test_web_analysis_calls_the_model_under_its_own_agent_name():
    llm = MagicMock()
    llm.call.return_value = "analysis text"
    agent = _web_agent(llm)

    out = agent._ai_web_analysis("http://127.0.0.1:3000", REPORT)

    assert out == "analysis text"
    assert llm.call.call_count == 1
    kwargs = llm.call.call_args.kwargs
    # A distinct agent_name is what makes the web path visible in llm.usage;
    # folding it into "exploit" would hide which path reached the model.
    assert kwargs["agent_name"] == "exploit_web"
    assert kwargs["cacheable_system"] is True


def test_web_analysis_sends_the_report_contents_not_just_a_shape():
    """A call that carries no report is the mutant this pins down.

    Asserting only that call() happened would pass with an empty prompt, so
    reach into the message and require the proof string itself.
    """
    llm = MagicMock()
    llm.call.return_value = "analysis text"
    agent = _web_agent(llm)

    agent._ai_web_analysis("http://127.0.0.1:3000", REPORT)

    user = llm.call.call_args.kwargs["messages"][0]["content"]
    assert "SQLITE_ERROR near syntax" in user
    assert "rest/products/search" in user
    assert "unauthorized_params" in user


def test_web_analysis_degrades_without_an_llm():
    """No model wired must not break the web phase for rule-based runs."""
    agent = _web_agent(None)

    out = agent._ai_web_analysis("http://127.0.0.1:3000", REPORT)

    assert "skipped" in out.lower()


def test_web_analysis_marks_the_report_as_target_written():
    """The report reaches the model inside a provenance marker.

    Every string in the report that matters here was written by the target:
    the URL, the parameter name, and the proof fragment lifted out of a
    response body. TrustGuard scrubs control characters on the way to the
    provider, but scrubbing says nothing about origin -- a parameter named
    to read as an instruction survives it intact. Until 23.08 the template
    interpolated the report bare, so the model saw target-authored text and
    operator-authored text as one undifferentiated block.

    The marker is a statement of provenance, not a sanitizer: it does not
    make the content safe, it makes its origin legible.
    """
    llm = MagicMock()
    llm.call.return_value = "analysis text"
    agent = _web_agent(llm)
    agent._ai_web_analysis("http://127.0.0.1:3000", REPORT)
    user = llm.call.call_args.kwargs["messages"][0]["content"]

    assert "[UNTRUSTED INPUT]" in user
    assert "[/UNTRUSTED INPUT]" in user

    # Target-written strings live inside the marked region, not before it.
    head, _, tail = user.partition("[UNTRUSTED INPUT]")
    assert "SQLITE_ERROR near syntax" not in head
    assert "rest/products/search" not in head
    body, _, _rest = tail.partition("[/UNTRUSTED INPUT]")
    assert "SQLITE_ERROR near syntax" in body
    assert "rest/products/search" in body
