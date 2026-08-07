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
