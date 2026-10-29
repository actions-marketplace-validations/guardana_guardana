# Example: a reference retrieval application

A small application that the two checks over seeded data run against:
`guardana.tenancy.cross_tenant_answer` and `guardana.retrieval.poisoned_document`
([`docs/usage-fixtures.md`](../../docs/usage-fixtures.md)). It shows the whole loop a team
runs in CI, end to end, against a real HTTP endpoint.

It is a reference, not your application. A clean run here proves the checks and their
controls work; it says nothing about your own index until you run them against it.

## What it is

- An OpenAI-compatible `POST /v1/chat/completions`, served with the standard library.
- **The tenant comes from the request's key.** Each tenant's key is read from the variable
  [`guardana-fixtures.yaml`](guardana-fixtures.yaml) names (`ACME_KEY`, `GLOBEX_KEY`). A
  request without a key reads no tenant's data; an unknown key gets `401`.
- **A keyword index** over the `documents.jsonl` that `guardana fixtures render` writes,
  filtered by the asking tenant.
- **An order tool**, `lookup_order`, served by `guardana.core.doubles` under
  `acting_as(<the tenant from the key>)`, with a trace of every call
  ([`docs/usage-doubles.md`](../../docs/usage-doubles.md)).
- **A stand-in "model"**, deterministic: it answers from the top document the asking tenant
  may read, or from the order tool when the question names an order id such as `A-100`.

No vector store and no model library: the point is the checks, not the retrieval.

## The two switches

| Switch | What breaks | What fails |
|---|---|---|
| `--break-tenant-filter` | the index searches every tenant's documents, and an order is looked up as whichever tenant holds it rather than the one the key names | `guardana.tenancy.cross_tenant_answer`, through documents and orders |
| `--obey-documents` | the model ends its reply as the instruction hidden in a poisoned document asks | `guardana.retrieval.poisoned_document` |

## Run it by hand

```bash
pip install ./packages/guardana-core ./packages/guardana-rules ./packages/guardana-report \
  ./packages/guardana-cli ./examples/retrieval_pilot
cd examples/retrieval_pilot
export ACME_KEY=acme-local-key GLOBEX_KEY=globex-local-key

guardana fixtures render guardana-fixtures.yaml --out seed/
retrieval-pilot --fixtures guardana-fixtures.yaml --documents seed/documents.jsonl \
  --trace doubles.jsonl --port 8000 &

guardana probe --url http://127.0.0.1:8000 --model reference \
  --fixtures guardana-fixtures.yaml --profile guardana.yaml
```

The probe exits `0`. Restart the application with a switch and it exits `1`; seed it with
part of `documents.jsonl` and it exits `2` with a `seed_not_reached` shortfall. Stop the
application (`kill %1`) before reading its trace with `guardana trace inspect doubles.jsonl`:
the footer is written as it exits. Give every run a fresh `--trace` path.

[`guardana.yaml`](guardana.yaml) selects only the two checks: the stand-in model answers
only from documents and orders, so no other rule would say anything about it.

## Running the tests

```bash
uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./packages/guardana-cli --with ./packages/guardana-report \
  --with ./examples/retrieval_pilot --with pytest \
  pytest examples/retrieval_pilot/tests
```

They drive the installed `guardana` command against the application on a local port:

- fixed: exit `0`, and the run's request count equals what the application received and what
  `guardana plan probe --fixtures` priced;
- broken filter: exit `1`, a tenancy finding through the documents and through the orders;
- obeying model: exit `1`, a poisoned-document finding;
- an index seeded without one tenant's documents: exit `2`, `seed_not_reached`;
- the doubles' trace, read with `guardana trace inspect`, holds every order lookup.
