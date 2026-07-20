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
    client = lc.LLMClient.__new__(lc.LLMClient)
    client.config = type("C", (), {"base_url": None, "model": "qwen2.5:7b"})()
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
    client = lc.LLMClient.__new__(lc.LLMClient)
    client.config = type("C", (), {"base_url": None, "model": "qwen2.5:7b"})()

    import pytest

    with pytest.raises(RuntimeError, match="ollama HTTP 400"):
        client._call_ollama([{"role": "user", "content": "hi"}], None)
