"""llm.usage was written by the orchestrator and read by nobody.

These pin the two consumers that a reader actually opens: the Markdown page
and the JSON export. The zero case matters most -- a refused provider is
exactly the run where the section has something to say.
"""

import json

from cyberai.agents.report.json_exporter import export_json
from cyberai.core.scan_session import ScanSession


def _session(**usage):
    s = ScanSession(target="http://127.0.0.1:3000")
    s.kb.set("llm.usage", usage, agent="orchestrator")
    return s


def test_the_json_export_carries_the_usage_from_disk(tmp_path):
    s = _session(provider="ollama", model="m", calls=0, attempts=1, zero_reason="provider_refused")
    path = export_json(s, output_dir=str(tmp_path))
    written = json.loads(open(path).read())
    assert written["llm_usage"]["zero_reason"] == "provider_refused"
    assert written["llm_usage"]["attempts"] == 1


def test_the_json_key_is_present_even_when_nothing_was_measured(tmp_path):
    s = ScanSession(target="http://127.0.0.1:3000")
    path = export_json(s, output_dir=str(tmp_path))
    written = json.loads(open(path).read())
    assert written["llm_usage"] == {}
