"""The credential follows the provider, not the other way round.

Measured before this existed, with both variables set and provider=anthropic:
config.api_key was 'sk-OPENAI-111' and that string was handed to
anthropic.Anthropic. ANTHROPIC_API_KEY was never read. The Anthropic SDK
only found its own key when the field stayed None, so the client worked when
nothing was configured and failed once an OpenAI key was present.
"""

from unittest.mock import MagicMock, patch

from cyberai.core.config import LLMConfig, RoutingConfig, api_key_for
from cyberai.core.cost_tracker import CostTracker
from cyberai.core.llm_client import LLMClient
from cyberai.core.model_router import ModelRouter
from cyberai.core.scan_session import ScanPhase


def _both_keys(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-OPENAI-111")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ANTHROPIC-222")


def test_anthropic_reads_its_own_variable(monkeypatch):
    _both_keys(monkeypatch)
    assert LLMConfig(provider="anthropic").api_key == "sk-ANTHROPIC-222"


def test_openai_reads_its_own_variable(monkeypatch):
    _both_keys(monkeypatch)
    assert LLMConfig(provider="openai").api_key == "sk-OPENAI-111"


def test_ollama_takes_no_key_even_when_both_are_set(monkeypatch):
    """A local runtime has no credential. None is the answer, not a gap."""
    _both_keys(monkeypatch)
    assert LLMConfig(provider="ollama").api_key is None
    assert api_key_for("ollama") is None


def test_an_explicit_key_is_not_overwritten(monkeypatch):
    _both_keys(monkeypatch)
    assert LLMConfig(provider="anthropic", api_key="sk-explicit").api_key == "sk-explicit"


def test_a_missing_variable_stays_none(monkeypatch):
    """Control: the assertions above read the environment, not a constant."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert LLMConfig(provider="anthropic").api_key is None


def test_the_anthropic_sdk_is_handed_the_anthropic_key(monkeypatch):
    _both_keys(monkeypatch)
    response = MagicMock()
    response.model = "m"
    response.usage.input_tokens = 1
    response.usage.output_tokens = 1
    response.usage.cache_creation_input_tokens = 0
    response.usage.cache_read_input_tokens = 0
    block = MagicMock()
    block.type = "text"
    block.text = "ok"
    response.content = [block]
    with patch("anthropic.Anthropic") as sdk:
        sdk.return_value.messages.create.return_value = response
        LLMClient(LLMConfig(provider="anthropic")).call([{"role": "user", "content": "x"}])
    assert sdk.call_args.kwargs["api_key"] == "sk-ANTHROPIC-222"


def test_an_air_gapped_route_does_not_carry_a_cloud_key(monkeypatch):
    """The router swaps the provider for a local one. Carrying the base
    credential over is the same defect in a second place."""
    _both_keys(monkeypatch)
    routing = RoutingConfig()
    router = ModelRouter(
        LLMConfig(provider="anthropic"),
        routing=routing,
        cost_tracker=CostTracker(),
        air_gapped=True,
    )
    client = router.client_for(ScanPhase.RECON)
    assert client.config.provider == routing.air_gapped_provider
    assert client.config.api_key is None
