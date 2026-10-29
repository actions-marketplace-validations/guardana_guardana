"""Named chat transports for self-hosted backends, selected by provider name.

The default `openai` transport (`UrllibTransport`) already covers any
OpenAI-compatible server — vLLM, llamafile, Ollama's `/v1`. These reach the two
backends that speak their own wire shape instead: Ollama's native `/api/chat`
and Hugging Face TGI's `/generate`. A provider is simply *which* `ChatTransport`
an `EndpointTarget` uses — no new entry-point group; a genuinely custom backend
still ships a `Target` through `guardana.targets`.
"""

from collections.abc import Callable, Sequence

from guardana.core.target.endpoint import (
    REQUEST_TIMEOUT_SECONDS,
    ChatMessage,
    ChatReply,
    ChatTransport,
    EndpointError,
    UrllibTransport,
    endpoint_ref,
    post_json,
)
from guardana.core.usage import TokenUsage


class OllamaTransport:
    """POSTs to Ollama's native `/api/chat` (non-streaming), reading its token counts."""

    def __init__(self, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """POST an Ollama chat request and return the reply text."""
        return self.send_reporting_usage(base_url, model, messages, api_key).text

    def send_reporting_usage(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> ChatReply:
        """POST an Ollama chat request and return the reply with the token counts it sent."""
        ref = endpoint_ref(base_url, model)
        payload = post_json(
            f"{base_url}/api/chat",
            {
                "model": model,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "stream": False,
            },
            api_key,
            ref,
            timeout=self._timeout,
        )
        if isinstance(payload, dict):
            message = payload.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return ChatReply(text=content, usage=_ollama_usage(payload))
        raise EndpointError(f"unexpected Ollama response from {ref}: {payload!r}")


def _ollama_usage(payload: dict[str, object]) -> TokenUsage | None:
    """Read Ollama's top-level counts; either may be absent (a cached prompt has no count)."""
    prompt = _count(payload.get("prompt_eval_count"))
    completion = _count(payload.get("eval_count"))
    if prompt is None and completion is None:
        return None
    return TokenUsage(input_tokens=prompt, output_tokens=completion)


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class TgiTransport:
    """POSTs to Hugging Face TGI `/generate` with the conversation flattened to a prompt."""

    def __init__(self, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """POST a TGI generate request and return the generated text."""
        ref = endpoint_ref(base_url, model)
        prompt = "\n".join(f"{m.role}: {m.content}" for m in messages)
        payload = post_json(
            f"{base_url}/generate",
            {"inputs": prompt, "parameters": {}},
            api_key,
            ref,
            timeout=self._timeout,
        )
        if isinstance(payload, list) and payload:
            payload = payload[0]
        if isinstance(payload, dict):
            text = payload.get("generated_text")
            if isinstance(text, str):
                return text
        raise EndpointError(f"unexpected TGI response from {ref}: {payload!r}")


_PROVIDERS: dict[str, Callable[[], ChatTransport]] = {
    "openai": UrllibTransport,
    "ollama": OllamaTransport,
    "tgi": TgiTransport,
}


def select_transport(provider: str) -> ChatTransport:
    """Return a fresh transport for a named provider, failing loudly on an unknown one."""
    factory = _PROVIDERS.get(provider)
    if factory is None:
        raise EndpointError(
            f"unknown provider {provider!r}; known: {', '.join(sorted(_PROVIDERS))}"
        )
    return factory()
