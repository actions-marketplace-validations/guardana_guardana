---
title: "Stateful tool doubles"
nav_order: 86
summary: "`guardana.core.doubles` serves the tools your fixtures file declares from an in-memory copy of its records, inside your application's process, enforcing tenancy as row-level security does, and writes every call into a trace you grade with `guardana analyze-trace`"
status: beta
---

# Stateful tool doubles — the tools your application calls in CI

In CI your application should not reach a real order system, mailbox or payment provider.
`guardana.core.doubles` serves the `tools:` of your [fixtures file](usage-fixtures.md) from
an in-memory copy of its `records:`, inside your application's own process, and writes every
call into a trace. The doubles behave as a backend that enforces tenancy: a call acts for
one tenant and sees only that tenant's records.

```python
from pathlib import Path

from guardana.core.doubles import open_doubles

doubles = open_doubles(Path("guardana-fixtures.yaml"), trace=Path("artifacts/doubles.jsonl"))


def handle(request):
    tenant = resolve_tenant(request)  # however your application decides who is asking
    with doubles.acting_as(tenant):
        return agent.run(
            request.message,
            tools={
                "lookup_order": doubles.tool("lookup_order"),
                "refund_order": doubles.tool("refund_order"),
            },
        )
```

Open the doubles once, at startup, where your application would build its real tool
clients, and only in CI. `doubles.call(name, **arguments)` calls a tool by name;
`doubles.tool(name)` returns it as a callable taking keyword arguments. Close them with
`doubles.close()` or by leaving a `with open_doubles(...) as doubles:` block; at interpreter
exit they close themselves.

`open_doubles` fails the application at startup, before anything is served, when:

- the fixtures file does not load (`FixturesError`, from `guardana.core.fixtures`), a tool's
  `sink` that a trace does not record included;
- the file declares no `tools:` (`DoublesError`);
- the trace path already exists. A file left by an earlier job, or one another process is
  writing, is never continued: give every job a fresh path.

## Who acts: `acting_as`

Every call acts for the tenant named by the innermost `with doubles.acting_as(tenant):`.
A call with no acting tenant, or naming a tenant the fixtures file does not declare, raises
`DoublesError` before anything is written, so an application that never says who is asking
fails its own tool call instead of reading someone's data.

The tenant is held in a context variable, so concurrent requests on different threads or
`asyncio` tasks each keep their own; a task created inside the block inherits it. A context
variable does not follow work into a `ThreadPoolExecutor`. Submit the work through a copy of
the current context, or enter `acting_as` inside the worker:

```python
import contextvars
from concurrent.futures import ThreadPoolExecutor

with doubles.acting_as(tenant), ThreadPoolExecutor() as pool:
    context = contextvars.copy_context()
    future = pool.submit(context.run, doubles.call, "lookup_order", id=order_id)
```

## What each tool does

| `op` | Arguments | Returns | Changes | In the trace |
|---|---|---|---|---|
| `get` | `id` | the acting tenant's record with that `id`, or `None` | nothing | the call, no effect |
| `search` | `query` | a list of the acting tenant's records whose retrieval term or any field value contains `query`, both case-folded | nothing | the call, no effect |
| `create` | `id` and the fields | the new record, owned by the acting tenant, or `None` when the `id` is taken in the collection | adds the record | the call and its effect, `failed` when refused |
| `update` | `id` and at least one field | the record as changed, or `None` when the acting tenant owns no record with that `id` | merges the fields | the call and its effect, `failed` when nothing was changed |
| `delete` | `id` | the removed record, or `None` when the acting tenant owns no record with that `id` | removes the record | the call and its effect, `failed` when nothing was removed |
| `send` | any JSON arguments | `{"sent": true}` | nothing | the call and its outbound effect |

- **A record comes back as its fields and its `id`.** A seeded record also carries
  `reference_code`, the presence marker Guardana derived for it
  ([markers](usage-fixtures.md#markers)); a record added by `create` has none. A field value
  is a string, a number or true/false; a call cannot write `reference_code`.
- **Another tenant's record is invisible**, exactly as one that does not exist, the way
  row-level security makes it. An `update` of another tenant's order returns `None` and
  changes nothing.
- **Arguments a tool does not take raise `DoublesError`** before anything is written: a
  missing or empty `id` or `query`, an extra argument to `get`, `search` or `delete`, an
  `update` that names no field, a field that is not a string, number or true/false, and a
  `send` whose arguments are not JSON data.
- **State lives as long as the process** and is shared by every call in it. It is never
  reset between cases: an order one case refunds stays refunded for the next.

A tenant leak through the doubles therefore needs your application to name the wrong
tenant. That is the bug to look for in the replies, where Guardana knows which tenant it
asked as; this trace cannot show it.

## The trace

```bash
guardana analyze-trace artifacts/doubles.jsonl
```

- **The file is created when the doubles open, and stays empty until the first call.** The
  header goes down with the first call's span in one write, so the file is either empty or
  holds a call, never a header alone that declares tools and effects over nothing. Doubles
  that were never called leave an empty file, which `analyze-trace` refuses with exit `3`:
  an application that never reached its tools is not a clean run.
- **Every span is flushed as it is written.** Closing the doubles, or the interpreter
  exiting, writes the footer that counts them. A process that is killed, or a call that could
  not be written, leaves no footer, and the trace reads as `unterminated`, so a rule that
  found nothing declines instead of passing. After a call that could not be written, the
  doubles refuse every further call.
- **A forked process refuses to write.** The doubles record the process that opened them; a
  call or a close from a child raises `DoublesError`, and a child that exits writes nothing.
  Open the doubles after forking, in each process, with a trace of its own.
- **The header** names the producer `guardana.doubles` and its version, declares `tools` and
  `effects` only, and carries the attributes `fixtures` (the file's `name`) and
  `fixtures_digest`.
- **Each call** is a `tool_execution` span named after the tool, whose `tool.arguments` is
  the call's arguments as JSON and whose status is `succeeded` or `failed`. A change or a send
  adds one effect on the tool's declared `sink`, with its declared `reversible`, the tool's
  name as `action`, `collection/id` as `target` (none for a send) and the status `executed` or
  `failed`. A read records no effect.

`analyze-trace` runs the rules that read tool calls and effects, such as a secret passed in
a tool argument, and skips those that need approvals, identity or retrieval, which this trace
does not record ([`usage-analyze-trace.md`](usage-analyze-trace.md)).

## Evidence, not the tenant verdict

The trace shows what your application did with its tools, for a reviewer and for the rules
that read tool calls and effects. It decides no tenant verdict: the tenant behind each call is
your application's own claim, and an application that named the wrong tenant would record a
call that looks correct. The trace records no tenant, no identity and no retrieval, because
every record a double returns belongs to the tenant the application named, so a cross-tenant
retrieval rule over it would run and could never fire.

## What Guardana cannot see

Guardana sees only the calls that go through the doubles. When your application also calls a
real tool beside them, an HTTP client left wired or a second SDK, nothing records it. Run the
application in CI without production credentials and without egress to production hosts, so
a real call fails loudly instead of succeeding unseen.

## Porting the doubles to another language

The doubles are a convenience in Python, not the only way in. A port behaves as the table
above, reads the records with their markers from `guardana.core.fixtures`
(`load_fixtures(path).records`, each with `served_fields()`), and writes the native trace
([`trace-v3.schema.json`](../schemas/trace-v3.schema.json),
[writing an integrator](writing-an-integrator.md)) under the same contract:

1. create the trace file exclusively, refusing one that exists;
2. hold the header back, declaring `terminated: true` and `instrumented: ["effects", "tools"]`,
   and write it with the first span in one write;
3. refuse a call with no tenant, or an undeclared one, and arguments the tool does not take,
   before anything is written;
4. flush every span; write the footer `{"guardana_trace_end": 3, "spans": N}` on close and
   at process exit, and never after a call that could not be written;
5. refuse to write from a process other than the one that opened the file.
