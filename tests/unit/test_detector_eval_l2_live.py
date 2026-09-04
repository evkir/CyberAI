"""The live L2 path, driven against a real server rather than a stand-in.

--l2 and --l2-record are the only branches of this command that talk to a
model, so no other test reaches them and coverage reported them missing.
Pointing the command at a socket that speaks ollama's shape exercises the
flag, the recording wrapper and the file it writes through the same code a
real run uses -- the default transport included.

The address had to become an option for that, which is not a concession to
the test: ollama does not have to sit on this host, and hard-coding that it
does was a defect the test happened to surface.
"""

import http.server
import json
import pathlib
import threading

import pytest
from click.testing import CliRunner

from cyberai.cli.detector_eval import detector
from cyberai.core.security.eval_corpus import load_corpus
from cyberai.core.security.llm_classifier import _fingerprint, recording_header

CORPUS = str(pathlib.Path(__file__).resolve().parents[2] / "tests" / "corpus")


class _Ollama(http.server.BaseHTTPRequestHandler):
    """Answers 'injection' for everything, which is enough to be recorded."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        body = json.dumps(
            {"message": {"content": json.dumps({"verdict": "injection", "reason": "r"})}}
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def served():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Ollama)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.mark.unit
def test_the_live_flag_scores_through_a_real_request(served):
    result = CliRunner().invoke(
        detector, ["eval", "--corpus", CORPUS, "--l2", "--l2-url", served, "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["layers"].startswith("L1+L2 (")
    assert payload["overall"]["true_positive"] == sum(
        1 for sample in load_corpus(CORPUS) if sample.is_injection
    )
    assert payload["blind_subclasses"] == []


@pytest.mark.unit
def test_a_recorded_run_writes_what_a_later_run_can_replay(tmp_path, served):
    """A recording is only worth writing if it loads again and scores the same.

    Asserted end to end rather than on the file's shape: the live run, the
    bytes it wrote and the replayed run all have to agree, which is the
    property the committed artifact's gate depends on.
    """
    recording = tmp_path / "nested" / "verdicts.json"
    live = CliRunner().invoke(
        detector,
        ["eval", "--corpus", CORPUS, "--l2", "--l2-url", served, "--l2-record", str(recording)],
    )
    assert live.exit_code == 0, live.output
    assert "verdicts recorded" in live.output

    body = json.loads(recording.read_text(encoding="utf-8"))
    assert set(body["verdicts"]) == {_fingerprint(s.text) for s in load_corpus(CORPUS)}

    replayed = CliRunner().invoke(
        detector, ["eval", "--corpus", CORPUS, "--l2-replay", str(recording), "--json"]
    )
    assert replayed.exit_code == 0, replayed.output

    live_again = CliRunner().invoke(
        detector, ["eval", "--corpus", CORPUS, "--l2", "--l2-url", served, "--json"]
    )
    assert json.loads(replayed.output)["overall"] == json.loads(live_again.output)["overall"]


@pytest.mark.unit
def test_a_recording_from_another_question_stops_the_run(tmp_path, served):
    """The refusal to merge has to reach the exit code, not just the writer.

    write_recording raising was already asserted at the function. What was
    not was that the command turns it into a failure: an exception that
    escapes as a traceback still ends the run, so the writer's test passes
    either way and a caller reading the exit code learns nothing.

    The message assertion is not decoration. Replacing the raise with a
    print leaves this run failing anyway -- the next statement reads a name
    the failed branch never bound -- so the exit code alone does not
    distinguish a refusal from a crash after one.
    """
    recording = tmp_path / "verdicts.json"
    header = recording_header("fast-coder:latest")
    header["prompt_sha256"] = "taken under an older prompt"
    recording.write_text(json.dumps({**header, "verdicts": {}}), encoding="utf-8")

    result = CliRunner().invoke(
        detector,
        ["eval", "--corpus", CORPUS, "--l2", "--l2-url", served, "--l2-record", str(recording)],
    )
    assert result.exit_code != 0
    assert "different prompt_sha256" in result.output
