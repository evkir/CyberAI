"""Prompt templates render without swallowing payload braces."""

from cyberai.core.prompts import WEB_EXPLOIT_PROMPT


def test_web_exploit_prompt_renders_both_placeholders():
    out = WEB_EXPLOIT_PROMPT.render(target="http://127.0.0.1:3000", report="{}")
    assert "http://127.0.0.1:3000" in out["user"]
    assert out["system"].startswith("You are an offensive security researcher")


def test_web_exploit_prompt_survives_json_report():
    """A report is JSON: literal braces must reach the model untouched.

    str.format is the renderer, so an unescaped brace in the template would
    raise here rather than silently dropping the payload.
    """
    report = '{"findings": [{"payload": "1\' OR 1=1", "proof": "SQLITE_ERROR"}]}'
    out = WEB_EXPLOIT_PROMPT.render(target="t", report=report)
    assert "SQLITE_ERROR" in out["user"]
    assert "1' OR 1=1" in out["user"]
