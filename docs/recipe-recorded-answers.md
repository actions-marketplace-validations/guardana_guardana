---
title: "Recipe: check a run your application recorded"
nav_order: 14
summary: "grade an execution your application already performed, from its trace or from the answers it gave, offline and without calling it"
status: stable
---

# Recipe: check a run your application recorded

Check an agent run that already happened, recorded as OpenTelemetry GenAI spans or in Guardana's native trace format. This works offline: it calls no model and invokes no tool.

```bash
guardana trace inspect trace.jsonl
guardana analyze-trace trace.jsonl --format json --output run.json
```

1. `trace inspect` shows what evidence the trace records. It also shows which rules cannot run because the trace lacks evidence they need.
2. `analyze-trace` grades the recorded execution and saves the run. If the trace lacks a type of evidence a rule needs, that rule does not run. The output identifies those rules; it never counts them as passed.

## Answers you supply yourself

When what your application recorded is its answers rather than a trace — a file of questions and replies — grade them with [`guardana grade`](usage-grade.md). It runs your suites and other chat rules over the answers and sends nothing to your application.

```bash
guardana grade answers.jsonl --rules rules/ --profile guardana.yaml --format json --output run.json
```

1. Write the answers as a [recording](usage-grade.md#a-recording): a header naming them and stating whether the replies are verbatim, then one line per question with your application's reply, naming the rule whose question it answers.
2. `grade` grades every recorded reply. A rule the recording holds no line for is skipped as `not_recorded`, which does not fail the default gate: select the rules it answers with `rules.include`, or use `--preset release`, which refuses the skip. Inside a rule the recording answers, a question it does not answer and a reply nobody asked for are errors that leave the run indeterminate, and an altered reply is never graded; none of them is counted as passed.
3. To grade a live probe's replies again — a new rule, a sharper expectation, another judge — run the probe once with `--keep-exchanges` and grade the file it keeps beside the run.

`analyze-trace` grades what a trace records, as described in [`usage-analyze-trace.md`](usage-analyze-trace.md).
