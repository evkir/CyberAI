import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import httpx

from .config import LLMConfig
from .cost_tracker import BudgetExceeded, CostTracker

if TYPE_CHECKING:
    from .base_agent import Tool


# Local models on a 3060 are slow on long exploit prompts; the async path
# used to allow only 60s and timed out where the sync path succeeded.
OLLAMA_TIMEOUT = 120


class LLMClient:
    """
    Unified LLM interface — OpenAI / Anthropic / Ollama
    One call() method regardless of provider.
    """

    def __init__(
        self,
        config: LLMConfig,
        cost_tracker: Optional[CostTracker] = None,
        budget_usd: float = 0.0,
    ):
        self.config = config
        self.cost_tracker = cost_tracker
        # Hard cap on cumulative LLM spend; 0.0 disables enforcement.
        self.budget_usd = budget_usd

    def _record_attempt(self) -> None:
        """Count the question. _record_usage counts the answer, and only a
        provider that replied reaches it -- a refusal has to be visible too."""
        if self.cost_tracker is not None:
            self.cost_tracker.record_attempt()

    def _record_usage(
        self,
        agent_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_creation_tokens: int = 0,
        cache_read_tokens: int = 0,
    ) -> None:
        """Append usage to the tracker, then enforce the budget if configured."""
        if self.cost_tracker is None:
            return
        self.cost_tracker.add(
            agent_name,
            model,
            input_tokens,
            output_tokens,
            cache_creation_tokens=cache_creation_tokens,
            cache_read_tokens=cache_read_tokens,
        )
        if self.budget_usd > 0:
            from .pricing import total_cost

            spent = total_cost(self.cost_tracker)
            if spent > self.budget_usd:
                raise BudgetExceeded(spent, self.budget_usd)

    def call(
        self,
        messages: List[Dict],
        system: Optional[str] = None,
        agent_name: str = "unknown",
        cacheable_system: bool = False,
    ) -> str:
        self._record_attempt()
        if self.config.provider == "openai":
            return self._call_openai(messages, system, agent_name)
        elif self.config.provider == "anthropic":
            return self._call_anthropic(messages, system, agent_name, cacheable_system)
        elif self.config.provider == "ollama":
            return self._call_ollama(messages, system, agent_name)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    def _call_openai(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        import openai

        client = openai.OpenAI(api_key=self.config.api_key)
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        response = client.chat.completions.create(
            model=self.config.model,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "prompt_tokens", 0),
            getattr(response.usage, "completion_tokens", 0),
        )
        return response.choices[0].message.content

    def _call_anthropic(
        self,
        messages: List[Dict],
        system: Optional[str],
        agent_name: str = "unknown",
        cacheable_system: bool = False,
    ) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self.config.api_key)
        kwargs: Dict[str, Any] = dict(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            messages=messages,
        )
        if system:
            kwargs["system"] = _wrap_cacheable(system) if cacheable_system else system
        response = client.messages.create(**kwargs)
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "input_tokens", 0),
            getattr(response.usage, "output_tokens", 0),
            cache_creation_tokens=getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        )
        return response.content[0].text

    def _ollama_request(self, messages: List[Dict], system: Optional[str]) -> tuple:
        """Build the (url, payload) pair for an ollama /api/chat call.

        Single source for both the sync and async entry points: the async one
        used to build its own payload and had silently dropped the system
        prompt and the raised num_ctx, so the same call behaved differently
        depending on which path reached it.
        """
        url = f"{self.config.base_url or 'http://localhost:11434'}/api/chat"
        full_messages: List[Dict] = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        payload = {
            "model": self.config.model,
            "messages": full_messages,
            "stream": False,
            # Default ollama context is 2048 tokens — too small for exploit
            # prompts (CVE JSON + attack paths + chain), which 4xx/5xx the call.
            "options": {"num_ctx": 8192},
        }
        return url, payload

    def _ollama_failure(self, response) -> RuntimeError:
        """Turn an ollama error response into a message that says what to do.

        A pulled-model default cannot be right for everyone: any name we ship
        is absent from someone's library, and the report agent swallows the
        exception by design, so a bare "HTTP 404" reached nobody. Name the
        model and the command that fixes it.
        """
        detail = response.text[:300]
        if response.status_code == 404:
            return RuntimeError(
                f"ollama has no model '{self.config.model}': "
                f"run `ollama pull {self.config.model}`, "
                f"or pick an installed one with --model. ({detail})"
            )
        return RuntimeError(f"ollama HTTP {response.status_code}: {detail}")

    def _call_ollama(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        url, payload = self._ollama_request(messages, system)
        response = httpx.post(url, json=payload, timeout=OLLAMA_TIMEOUT)
        if response.status_code != 200:
            raise self._ollama_failure(response)
        data = response.json()
        self._record_usage(
            agent_name,
            data.get("model", self.config.model),
            data.get("prompt_eval_count", 0),
            data.get("eval_count", 0),
        )
        return data["message"]["content"]

    # ── native tool calling (sync) ────────────────────────────────────

    def call_tools(
        self,
        messages: List[Dict],
        system: Optional[str] = None,
        tools: Optional[List["Tool"]] = None,
        agent_name: str = "unknown",
        cacheable_system: bool = False,
    ) -> "LLMResponse":
        """One tool-enabled round-trip. Ollama tool calling is unsupported."""
        self._record_attempt()
        tools = tools or []
        if self.config.provider == "openai":
            return self._call_tools_openai(messages, system, tools, agent_name)
        elif self.config.provider == "anthropic":
            return self._call_tools_anthropic(messages, system, tools, agent_name, cacheable_system)
        else:
            raise ValueError(f"Tool calling unsupported for provider: {self.config.provider}")

    def _call_tools_openai(self, messages, system, tools, agent_name="unknown"):
        import openai

        client = openai.OpenAI(api_key=self.config.api_key)
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        response = client.chat.completions.create(
            model=self.config.model,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            tools=_tools_to_openai_format(tools),
        )
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "prompt_tokens", 0),
            getattr(response.usage, "completion_tokens", 0),
        )
        choice = response.choices[0]
        msg = choice.message
        calls = []
        for tc in getattr(msg, "tool_calls", None) or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
        return LLMResponse(text=msg.content, tool_calls=calls, stop_reason=choice.finish_reason)

    def _call_tools_anthropic(
        self, messages, system, tools, agent_name="unknown", cacheable_system=False
    ):
        import anthropic

        client = anthropic.Anthropic(api_key=self.config.api_key)
        kwargs: Dict[str, Any] = dict(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            messages=messages,
            tools=_tools_to_anthropic_format(tools),
        )
        if system:
            kwargs["system"] = _wrap_cacheable(system) if cacheable_system else system
        response = client.messages.create(**kwargs)
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "input_tokens", 0),
            getattr(response.usage, "output_tokens", 0),
            cache_creation_tokens=getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        )
        text_parts = []
        calls = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))
        return LLMResponse(
            text="".join(text_parts) or None,
            tool_calls=calls,
            stop_reason=getattr(response, "stop_reason", None),
        )

    # ── structured output (sync) ──────────────────────────────────────

    def structured_call(
        self,
        messages: List[Dict],
        schema: Dict[str, Any],
        schema_name: str = "response",
        description: str = "",
        system: Optional[str] = None,
        agent_name: str = "unknown",
        cacheable_system: bool = False,
    ) -> Dict[str, Any]:
        """Force the model to return JSON matching `schema`; returns parsed dict.

        OpenAI: response_format=json_schema. Anthropic: a single forced tool
        whose input_schema is `schema` — the tool_use input IS the structured
        output. Ollama: the schema goes in `format`, which constrains decoding
        server-side. Caller validates via pydantic.
        """
        self._record_attempt()
        if self.config.provider == "openai":
            return self._structured_openai(
                messages, schema, schema_name, description, system, agent_name
            )
        elif self.config.provider == "anthropic":
            return self._structured_anthropic(
                messages,
                schema,
                schema_name,
                description,
                system,
                agent_name,
                cacheable_system,
            )
        elif self.config.provider == "ollama":
            return self._structured_ollama(
                messages, schema, schema_name, description, system, agent_name
            )
        else:
            raise ValueError(f"Structured output unsupported for provider: {self.config.provider}")

    @staticmethod
    def _schema_all_required(schema: Dict[str, Any]) -> Dict[str, Any]:
        """Copy of `schema` with every declared property marked required.

        Left alone, a schema that requires only one field lets a constrained
        decoder emit that field and stop. Measured on qwen2.5-coder:14b at
        temperature 0: severity fell back to its default and impact came back
        empty, producing a section that parses cleanly and states nothing --
        and a default severity is not an absent claim, it is a wrong one.
        """
        props = schema.get("properties")
        if not isinstance(props, dict) or not props:
            return schema
        widened = dict(schema)
        widened["required"] = sorted(props.keys())
        return widened

    def _structured_ollama(
        self, messages, schema, schema_name, description, system, agent_name="unknown"
    ):
        """Structured output on a local model, constrained by the server.

        ollama takes a JSON Schema in `format` and restricts generation to it,
        so the local path gets the same guarantee as the hosted ones instead of
        asking the model politely for JSON. This is what makes the air-gapped
        path complete: previously this provider raised, and the report agent
        swallowed that into a silently missing section.
        """
        url, payload = self._ollama_request(messages, system)
        payload["format"] = self._schema_all_required(schema)
        response = httpx.post(url, json=payload, timeout=OLLAMA_TIMEOUT)
        if response.status_code != 200:
            raise self._ollama_failure(response)
        data = response.json()
        self._record_usage(
            agent_name,
            data.get("model", self.config.model),
            data.get("prompt_eval_count", 0),
            data.get("eval_count", 0),
        )
        return json.loads(data["message"]["content"])

    def _structured_openai(
        self, messages, schema, schema_name, description, system, agent_name="unknown"
    ):
        import openai

        client = openai.OpenAI(api_key=self.config.api_key)
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        response = client.chat.completions.create(
            model=self.config.model,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "schema": schema,
                    "strict": False,
                },
            },
        )
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "prompt_tokens", 0),
            getattr(response.usage, "completion_tokens", 0),
        )
        content = response.choices[0].message.content or "{}"
        return json.loads(content)

    def _structured_anthropic(
        self,
        messages,
        schema,
        schema_name,
        description,
        system,
        agent_name="unknown",
        cacheable_system=False,
    ):
        import anthropic

        client = anthropic.Anthropic(api_key=self.config.api_key)
        tool = {
            "name": schema_name,
            "description": description or f"Return a structured {schema_name}.",
            "input_schema": schema,
        }
        kwargs: Dict[str, Any] = dict(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            messages=messages,
            tools=[tool],
            tool_choice={"type": "tool", "name": schema_name},
        )
        if system:
            kwargs["system"] = _wrap_cacheable(system) if cacheable_system else system
        response = client.messages.create(**kwargs)
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "input_tokens", 0),
            getattr(response.usage, "output_tokens", 0),
            cache_creation_tokens=getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        )
        for block in response.content:
            if block.type == "tool_use":
                return dict(block.input)
        return {}

    # ── async API ─────────────────────────────────────────────────────

    async def acall(
        self,
        messages: List[Dict],
        system: Optional[str] = None,
        agent_name: str = "unknown",
        cacheable_system: bool = False,
    ) -> str:
        """Async equivalent of call() — same return type, same provider routing."""
        self._record_attempt()
        if self.config.provider == "openai":
            return await self._acall_openai(messages, system, agent_name)
        elif self.config.provider == "anthropic":
            return await self._acall_anthropic(messages, system, agent_name, cacheable_system)
        elif self.config.provider == "ollama":
            return await self._acall_ollama(messages, system, agent_name)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    async def _acall_openai(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        import openai

        client = openai.AsyncOpenAI(api_key=self.config.api_key)
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        response = await client.chat.completions.create(
            model=self.config.model,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "prompt_tokens", 0),
            getattr(response.usage, "completion_tokens", 0),
        )
        return response.choices[0].message.content

    async def _acall_anthropic(
        self,
        messages: List[Dict],
        system: Optional[str],
        agent_name: str = "unknown",
        cacheable_system: bool = False,
    ) -> str:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self.config.api_key)
        kwargs: Dict[str, Any] = dict(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            messages=messages,
        )
        if system:
            kwargs["system"] = _wrap_cacheable(system) if cacheable_system else system
        response = await client.messages.create(**kwargs)
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "input_tokens", 0),
            getattr(response.usage, "output_tokens", 0),
            cache_creation_tokens=getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        )
        return response.content[0].text

    async def _acall_ollama(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        url, payload = self._ollama_request(messages, system)
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
        self._record_usage(
            agent_name,
            data.get("model", self.config.model),
            data.get("prompt_eval_count", 0),
            data.get("eval_count", 0),
        )
        return data["message"]["content"]


def _wrap_cacheable(system_text: str) -> list[dict]:
    """
    Wrap a system prompt in Anthropic's cache_control format.

    The minimum cacheable block is 1024 tokens (Sonnet/Opus) or 2048 (Haiku);
    smaller blocks are silently ignored by the API and billed at full rate.
    Default TTL is 5 minutes, refreshed on each cache hit.
    """
    return [
        {
            "type": "text",
            "text": system_text,
            "cache_control": {"type": "ephemeral"},
        }
    ]


# ── native tool calling: response types + spec converters ─────────────


@dataclass
class ToolCall:
    """A single tool invocation requested by the model."""

    id: str
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Tool-enabled call result: free text and/or requested tool calls."""

    text: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    stop_reason: Optional[str] = None


def _params_to_schema(tool: "Tool") -> Dict[str, Any]:
    """JSON Schema for a Tool's arguments.

    Prefers tool.input_schema when set; otherwise derives an all-string
    object schema from tool.params (arg name -> description). params cannot
    express non-string/nested types — set input_schema for those.
    """
    explicit = getattr(tool, "input_schema", None)
    if explicit:
        return explicit
    props = {
        name: {"type": "string", "description": desc}
        for name, desc in (getattr(tool, "params", None) or {}).items()
    }
    return {"type": "object", "properties": props, "required": list(props)}


def _tools_to_openai_format(tools: List["Tool"]) -> List[Dict[str, Any]]:
    """Convert Tools to the OpenAI chat.completions `tools` shape."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": _params_to_schema(t),
            },
        }
        for t in tools
    ]


def _tools_to_anthropic_format(tools: List["Tool"]) -> List[Dict[str, Any]]:
    """Convert Tools to the Anthropic messages `tools` shape.

    Anthropic uses a flat {name, description, input_schema} per tool,
    where input_schema is the JSON Schema for the arguments object.
    """
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": _params_to_schema(t),
        }
        for t in tools
    ]


# ── native tool calling: provider-aware message threading ─────────────


def format_assistant_tool_turn(provider: str, response: "LLMResponse") -> Dict[str, Any]:
    """Rebuild the assistant turn that requested tool calls, for re-sending."""
    if provider == "anthropic":
        content: List[Dict[str, Any]] = []
        if response.text:
            content.append({"type": "text", "text": response.text})
        for tc in response.tool_calls:
            content.append(
                {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments}
            )
        return {"role": "assistant", "content": content}
    return {
        "role": "assistant",
        "content": response.text,
        "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
            }
            for tc in response.tool_calls
        ],
    }


def format_tool_results(provider: str, results: List[tuple]) -> List[Dict[str, Any]]:
    """results: list of (ToolCall, output_str) -> provider-shaped messages."""
    if provider == "anthropic":
        return [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": tc.id, "content": out}
                    for tc, out in results
                ],
            }
        ]
    return [{"role": "tool", "tool_call_id": tc.id, "content": out} for tc, out in results]
