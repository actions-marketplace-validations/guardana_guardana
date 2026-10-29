---
paths:
  - "examples/**"
---
# Examples — the third-party story, and one deliberate poison

- **`examples/vulnerable-model/` is deliberately malicious** (a pickle that calls `os.system`).
  `guardana scan .` is supposed to exit 1; the dogfood gate scans `packages/`. Never "fix" the
  fixture, never exclude it from a scan to make a demo green; ruff excludes it on purpose.
- **`reference_pack` is the extension contract whole**: the distribution
  `guardana-reference-pack`, versioned on its own and attached to every GitHub Release, using
  all six entry-point groups and only the supported surface — its suite walks its imports and
  refuses anything else, and proves the pack only with what Guardana ships (`rule test`, the
  conformance kit, `pack validate`, `pack lock --check`, a `scan`). Its committed lock holds
  its own entry only; regenerate it when a rule changes, and bump the pack's version by hand.
- **The other isolated suites; four are the extension contract one idea at a time**:
  `custom_rule` (consumer: rules, evaluators, targets, taxonomies through all four entry-point
  groups), `hermes_integrator` (producer: a third party's entry-point group, one file per
  session), `shell_hook_integrator` (producer: a command spawned per event, three processes
  sharing a file — the only gate that exercises `resume_trace` across real process boundaries)
  and `output_pack` (an installed format and reporter through `guardana.renderers` and
  `guardana.reporters`, selected only when named; `scan` and `grade` run with the network
  refused, and the webhook is checked by `standardwebhooks`, which only that suite installs).
- **`retrieval_pilot` is an isolated suite, not an extension**: a reference application
  served on a local port, probed through the installed CLI with `--fixtures`. It runs only the
  two checks over seeded data (its `guardana.yaml`), because its "model" is a stand-in; keep it
  free of a vector store or model library.
- **Run them isolated and with `--no-cache`**: `uv run --isolated --no-cache --with
  ./packages/guardana-core … --with ./examples/<name> --with pytest pytest
  examples/<name>/tests -q`. A cached wheel hides exactly the data files (`guardana-pack.yaml`,
  the YAML rules) an extension change touches; `--refresh` does not help. Installing `acme.*`
  into the main environment would skew the dogfood scan, which is why `uv run pytest` cannot
  see these.
- **Integrators never import the agent they integrate**; payloads are copied from upstream
  documentation, which keeps them runnable in CI. Checking against the real thing is a manual
  step each README documents.
- A change to `Rule`, `Evaluator`, `Target`, any of the six entry-point groups, the output
  contract (`guardana.core.output`), the pack manifest or lock, or the trace format is not done
  until every example suite is green here: `custom_rule`, `hermes_integrator`,
  `shell_hook_integrator`, `output_pack`, `retrieval_pilot` and `reference_pack`.
