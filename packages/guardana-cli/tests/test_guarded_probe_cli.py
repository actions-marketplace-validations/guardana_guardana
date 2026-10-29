"""A probe through an adapter whose guard declines some requests, and the grade of what it kept.

The application answers one prompt, declines one as a policy refusal and one as input it
will not take. The saved run grades each as the adapter declared it, the kept recording
holds the two declines in place of replies, and grading that recording reaches the same
verdicts without sending anything.
"""

import json
from pathlib import Path
from typing import Any

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.testing._fake_provider import FakeProvider, adapter_reply
from typer.testing import CliRunner

runner = CliRunner()

_RULE = (
    "id: {id}\n"
    "title: {id}\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "taxonomy: [LLM01:2025]\n"
    "evaluator: keyword\n"
    "requires: [chat]\n"
    "prompts: ['{id} asks']\n"
)
_ANSWERED, _REFUSED, _UNGRADED = "acme.a.answered", "acme.b.refused", "acme.c.ungraded"
_ADAPTER = """\
url: {url}/chat
body:
  message: "{{{{prompt}}}}"
response_path: data.reply
declines:
  - name: content_filter
    status: 400
    path: error.code
    equals: content_policy
    as: refusal
  - name: input_rejected
    status: 413
    as: ungraded
metadata_paths:
  request_id: meta.request_id
"""


def _setup(tmp_path: Path, url: str) -> tuple[list[str], str]:
    rules = tmp_path / "rules"
    rules.mkdir()
    for rule_id in (_ANSWERED, _REFUSED, _UNGRADED):
        (rules / f"{rule_id}.yaml").write_text(_RULE.format(id=rule_id), encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\nrules:\n  include: ['acme.*']\n", encoding="utf-8")
    adapter = tmp_path / "adapter.yaml"
    adapter.write_text(_ADAPTER.format(url=url), encoding="utf-8")
    return ["--rules", str(rules), "--profile", str(profile)], str(adapter)


def _by_rule(document: dict[str, Any]) -> dict[str, tuple[object, ...]]:
    return {
        a["rule_id"]: (a["status"], a["passed"], a.get("reason"), tuple(a.get("tags", ())))
        for a in document["assessments"]
    }


def test_a_guarded_probe_grades_each_decline_as_declared_and_its_recording_grades_the_same(
    tmp_path: Path,
) -> None:
    script = (
        adapter_reply("I cannot help with that.", fields={"meta": {"request_id": "r-1"}}),
        adapter_reply(
            None,
            fields={"error": {"code": "content_policy"}, "meta": {"request_id": "r-2"}},
            status=400,
        ),
        adapter_reply(None, fields={"error": "too large"}, status=413),
    )
    with FakeProvider(*script) as provider:
        selection, adapter = _setup(tmp_path, provider.url)
        probed = runner.invoke(
            app,
            [
                "probe",
                "--url",
                f"{provider.url}/chat",
                "--model",
                "app",
                "--adapter",
                adapter,
                *selection,
                "--concurrency",
                "1",
                "--keep-exchanges",
                "--format",
                "json",
                "--output",
                str(tmp_path / "run.json"),
            ],
        )
        sent = len(provider.requests)

    assert probed.exit_code in {ExitCode.OK, ExitCode.INDETERMINATE}, probed.output
    assert sent == 3, "a decline is one request and is never retried"
    run = json.loads((tmp_path / "run.json").read_text("utf-8"))
    probed_verdicts = _by_rule(run)
    assert probed_verdicts == {
        _ANSWERED: ("measured", True, None, ()),
        _REFUSED: ("measured", True, None, ("declined:content_filter",)),
        _UNGRADED: ("inconclusive", None, "target_declined", ("declined:input_rejected",)),
    }
    assert run["findings"] == []
    unverified = run["unverified"]
    assert [f["rule_id"] for f in unverified] == [_UNGRADED]
    assert "declined by the application: input_rejected (HTTP 413)" in json.dumps(unverified)

    sidecar = tmp_path / "run.exchanges.jsonl"
    header, *lines = (json.loads(line) for line in sidecar.read_text("utf-8").splitlines())
    assert header["guardana_recording"] == 3
    kept = {line["rule"]: line for line in lines}
    assert kept[_ANSWERED]["reply"] == "I cannot help with that."
    assert kept[_ANSWERED]["meta"] == {"request_id": "r-1"}
    assert kept[_REFUSED]["declined"] == {
        "name": "content_filter",
        "reading": "refusal",
        "status": 400,
    }
    assert kept[_REFUSED]["meta"] == {"request_id": "r-2"}
    assert "reply" not in kept[_REFUSED]
    assert kept[_UNGRADED]["declined"]["reading"] == "ungraded"

    graded = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            *selection,
            "--format",
            "json",
            "--output",
            str(tmp_path / "graded.json"),
        ],
    )

    assert graded.exit_code == probed.exit_code, graded.output
    regraded = json.loads((tmp_path / "graded.json").read_text("utf-8"))
    assert _by_rule(regraded) == probed_verdicts
    assert regraded["run"]["result_summary"]["gate"] == run["run"]["result_summary"]["gate"]
    assert regraded["run"]["usage"]["requests"] == 0
