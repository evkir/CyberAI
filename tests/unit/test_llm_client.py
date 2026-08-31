def test_call_ollama_includes_system_and_num_ctx(monkeypatch):
    """Ollama payload must carry the system prompt and a raised num_ctx so
    large exploit prompts don't overflow the default 2048-token context."""
    from cyberai.core import llm_client as lc

    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"message": {"content": "ok"}}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return _Resp()

    monkeypatch.setattr(lc.httpx, "post", fake_post)
    client = lc.LLMClient(lc.LLMConfig(provider="ollama", model="qwen2.5:7b"))
    client.cost_tracker = None
    out = client._call_ollama([{"role": "user", "content": "hi"}], "SYS")

    assert out == "ok"
    assert captured["payload"]["messages"][0] == {"role": "system", "content": "SYS"}
    assert captured["payload"]["options"]["num_ctx"] == 8192


def test_call_ollama_surfaces_http_error(monkeypatch):
    """A non-200 from ollama must raise with the real status + body so the
    cause is diagnosable (not a bare HTTPStatusError)."""
    from cyberai.core import llm_client as lc

    class _Resp:
        status_code = 400
        text = "context length exceeded"

    monkeypatch.setattr(lc.httpx, "post", lambda url, json, timeout: _Resp())
    client = lc.LLMClient(lc.LLMConfig(provider="ollama", model="qwen2.5:7b"))
    client.cost_tracker = None

    import pytest

    with pytest.raises(RuntimeError, match="ollama HTTP 400"):
        client._call_ollama([{"role": "user", "content": "hi"}], None)


def test_call_ollama_records_usage(monkeypatch):
    """Local ollama calls must be counted so 'LLM calls: 0' is no longer a lie."""
    from cyberai.core import llm_client as lc
    from cyberai.core.cost_tracker import CostTracker

    class _Resp:
        status_code = 200

        def json(self):
            return {
                "model": "qwen2.5:7b",
                "message": {"content": "ok"},
                "prompt_eval_count": 42,
                "eval_count": 7,
            }

    monkeypatch.setattr(lc.httpx, "post", lambda url, json, timeout: _Resp())
    client = lc.LLMClient(lc.LLMConfig(provider="ollama", model="qwen2.5:7b"))
    client.cost_tracker = CostTracker()
    client.budget_usd = 0

    out = client.call([{"role": "user", "content": "hi"}], "SYS", agent_name="exploit")

    assert out == "ok"
    assert client.cost_tracker.call_count == 1
    assert client.cost_tracker.total_input_tokens == 42
    assert client.cost_tracker.total_output_tokens == 7
    assert client.cost_tracker.calls[0].agent == "exploit"


def test_call_ollama_missing_eval_counts_default_zero(monkeypatch):
    """Ollama responses without eval counts still record a call at 0/0 tokens."""
    from cyberai.core import llm_client as lc
    from cyberai.core.cost_tracker import CostTracker

    class _Resp:
        status_code = 200

        def json(self):
            return {"message": {"content": "ok"}}

    monkeypatch.setattr(lc.httpx, "post", lambda url, json, timeout: _Resp())
    client = lc.LLMClient(lc.LLMConfig(provider="ollama", model="qwen2.5:7b"))
    client.cost_tracker = CostTracker()
    client.budget_usd = 0

    client._call_ollama([{"role": "user", "content": "hi"}], None, agent_name="intel")

    assert client.cost_tracker.call_count == 1
    assert client.cost_tracker.total_input_tokens == 0
    assert client.cost_tracker.calls[0].agent == "intel"


def test_acall_ollama_records_usage(monkeypatch):
    """Async ollama path records usage identically to the sync path."""
    import asyncio

    from cyberai.core import llm_client as lc
    from cyberai.core.cost_tracker import CostTracker

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "model": "qwen2.5:7b",
                "message": {"content": "ok"},
                "prompt_eval_count": 10,
                "eval_count": 3,
            }

    class _AsyncClient:
        def __init__(self, timeout):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            return _Resp()

    monkeypatch.setattr(lc.httpx, "AsyncClient", _AsyncClient)
    client = lc.LLMClient(lc.LLMConfig(provider="ollama", model="qwen2.5:7b"))
    client.cost_tracker = CostTracker()
    client.budget_usd = 0

    out = asyncio.run(client.acall([{"role": "user", "content": "hi"}], None, agent_name="exploit"))

    assert out == "ok"
    assert client.cost_tracker.call_count == 1
    assert client.cost_tracker.total_input_tokens == 10
    assert client.cost_tracker.total_output_tokens == 3


def test_ollama_sync_and_async_send_identical_payloads(monkeypatch):
    """Both ollama entry points must build the same request body. The async
    one used to construct its own, dropping the system prompt and the raised
    num_ctx, so the same prompt behaved differently depending on the path."""
    import asyncio

    from cyberai.core import llm_client as lc

    captured = {}

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "ok"}}

    def fake_post(url, json, timeout):
        captured["sync"] = (url, json, timeout)
        return _Resp()

    class _AsyncClient:
        def __init__(self, timeout):
            captured["async_timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            captured["async"] = (url, json)
            return _Resp()

    monkeypatch.setattr(lc.httpx, "post", fake_post)
    monkeypatch.setattr(lc.httpx, "AsyncClient", _AsyncClient)

    client = lc.LLMClient(lc.LLMConfig(provider="ollama", model="qwen2.5:7b"))
    client.cost_tracker = None
    client.budget_usd = 0

    messages = [{"role": "user", "content": "hi"}]
    client._call_ollama(messages, "SYS")
    asyncio.run(client._acall_ollama(messages, "SYS"))

    sync_url, sync_payload, sync_timeout = captured["sync"]
    async_url, async_payload = captured["async"]
    assert sync_url == async_url
    assert sync_payload == async_payload
    assert sync_timeout == captured["async_timeout"] == lc.OLLAMA_TIMEOUT
    assert async_payload["messages"][0] == {"role": "system", "content": "SYS"}
    assert async_payload["options"]["num_ctx"] == 8192


def test_every_ollama_entry_point_carries_the_configured_sampling(monkeypatch):
    """All three ollama entry points must send the configured temperature, and
    a seed only when one was pinned.

    Measured before the fix: eight identical product calls returned eight
    different answers, because the payload carried neither value and ollama
    sampled with a random seed. The same eight calls with temperature and
    seed added by hand returned one. The structured entry point had no test
    at all, so it is asserted here alongside the other two rather than
    trusted to share their builder forever.
    """
    import asyncio

    from cyberai.core import llm_client as lc

    captured = {}

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "{}"}}

    class _AsyncClient:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            captured["async"] = json
            return _Resp()

    def _options_from_every_entry_point(config):
        client = lc.LLMClient(config)
        client.cost_tracker = None
        client.budget_usd = 0
        messages = [{"role": "user", "content": "hi"}]

        def fake_post(url, json, timeout):
            captured["sync"] = json
            return _Resp()

        monkeypatch.setattr(lc.httpx, "post", fake_post)
        monkeypatch.setattr(lc.httpx, "AsyncClient", _AsyncClient)

        client._call_ollama(messages, "SYS")
        sync_options = captured["sync"]["options"]

        client._structured_ollama(messages, {"type": "object"}, "S", "d", "SYS")
        structured_options = captured["sync"]["options"]

        asyncio.run(client._acall_ollama(messages, "SYS"))
        async_options = captured["async"]["options"]

        return {
            "sync": sync_options,
            "structured": structured_options,
            "async": async_options,
        }

    unpinned = _options_from_every_entry_point(
        lc.LLMConfig(provider="ollama", model="qwen2.5:7b", temperature=0.35)
    )
    pinned = _options_from_every_entry_point(
        lc.LLMConfig(provider="ollama", model="qwen2.5:7b", temperature=0.0, seed=7)
    )

    carries_temperature = {n: o.get("temperature") for n, o in unpinned.items()}
    carries_no_seed = {n: ("seed" in o) for n, o in unpinned.items()}
    carries_seed = {n: o.get("seed") for n, o in pinned.items()}

    assert carries_temperature == {"sync": 0.35, "structured": 0.35, "async": 0.35}
    assert carries_no_seed == {"sync": False, "structured": False, "async": False}
    assert carries_seed == {"sync": 7, "structured": 7, "async": 7}
