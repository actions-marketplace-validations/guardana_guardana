---
title: "Providers"
nav_order: 165
summary: "What each way of reaching a model carries — the system message, tools, token counts, tool turns — and which failures it retries"
status: stable
---

# What each provider carries

Guardana reaches a model through one of a few transports: the built-in `openai`,
`ollama` and `tgi` providers (`--provider`), an adapter file for your own product
endpoint (`--adapter`), or a LangChain chat model from Python. They do not all carry
the same things. Where one cannot carry something, Guardana refuses the check or the
budget that depends on it rather than reporting a result it never measured.

The table below is checked by the test suite against a local stand-in for each
provider, so it states what the code does, not what it intends.

| transport | system message | tools | token usage | tool turns in history | retried statuses |
|---|---|---|---|---|---|
| `openai` | role | carried | carried | carried | 429, 500, 502, 503, 504 |
| `ollama` | role | not carried: no `call_tools` capability | carried | not carried: no `call_tools` capability | 429, 500, 502, 503, 504 |
| `tgi` | flattened | not carried: no `call_tools` capability | not carried: a token ceiling is refused | not carried: no `call_tools` capability | 429, 500, 502, 503, 504 |
| adapter with a `{{system}}` slot | slot | not carried: no `call_tools` capability | not carried: a token ceiling is refused | not carried: no `call_tools` capability | 429, 503 |
| adapter without a `{{system}}` slot | folded | not carried: no `call_tools` capability | not carried: a token ceiling is refused | not carried: no `call_tools` capability | 429, 503 |
| LangChain, a model that binds tools | role | carried | carried | carried | not applicable |
| LangChain, a model that cannot bind tools | role | not carried: no `call_tools` capability | carried | carried | not applicable |

## Reading the columns

**System message** — how a system prompt (yours, or a planted canary) reaches the model:

- *role*: a message with the `system` role.
- *flattened*: one `role: content` line per message in a single raw prompt.
- *slot*: the adapter's `{{system}}` placeholder receives it, apart from the prompt.
- *folded*: the adapter has no `{{system}}` slot, so the system message and every turn
  are written into `{{prompt}}` as a labelled transcript (`System: …`, `User: …`).

**Tools** — whether a tool can be offered and the model's calls read back. Without it
the target does not declare the `call_tools` capability, so the agentic checks are
skipped with a reason and `guardana target inspect` shows tool calling as unavailable.

**Token usage** — whether the reply's token counts are read. When a reply carries
none, the run records the request with unknown counts, never zero. A token ceiling
(`max_input_tokens`, `max_output_tokens`) over a transport that cannot report counts
is refused before the first request; one over a reply that arrives without a count
stops the run as one whose budget can no longer be held.

**Tool turns in history** — whether an earlier tool call and its result reach the
model on the next turn. Every transport that offers tools carries them.

**Retried statuses** — the HTTP statuses retried, at most three attempts, honouring
`Retry-After` up to 30 seconds. Every retry is another request: it counts against
`max_requests` and in the run's usage. The adapter does not retry `500`, `502` or
`504` by default, because your application may have acted before it failed. The adapter
rows show its default: an adapter file's `retry_statuses:` replaces the set with statuses
from `408`, `425`, `429` and `500`–`599`, and `[]` retries nothing
([guarded endpoint](usage-probe.md#declines-retried-statuses-and-metadata)). A reply an
adapter's `declines:` matches is never retried. The built-in providers keep their fixed set.

## Every HTTP transport, alike

- `401`, `403` and `404` fail on the first attempt, without a retry.
- A redirect is refused and never followed.
- A reply that is not JSON, lacks the reply text, or exceeds 8 MiB fails the
  request; it is never graded as an empty answer.
- A reply slower than the request timeout (30 seconds), a connection reset while
  sending, or a reply that is not HTTP fails the request without a retry.
- A `4xx` other than `401`, `403`, `404`, `407`, `408`, `425` and `429`, once raised,
  is an error of the rule that sent it and the run goes on; any other failure that
  survives the retries stops the run as the target's
  ([probe](usage-probe.md#when-the-target-fails-part-way)).

None of these apply to LangChain, which calls the chat model in-process.
