"""The samples `guardana rule test` runs the two seeded checks against, built in code.

One fixtures file written here and one application double over it; each sample flips
one switch of the double, so what a sample proves is readable from its arguments.
"""

from pathlib import Path

from guardana.core.fixtures import DOCUMENTS_CHANNEL, Fixtures, parse_fixtures
from guardana.core.rule import Rule
from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome
from guardana.core.target import SeededTarget
from guardana.core.testing.seeded import SeededApplication, seeded_target

SAMPLE_FIXTURES = """\
schema_version: 1
name: rule-samples
data: synthetic
tenants:
  acme: {api_key_env: ACME_KEY}
  globex: {api_key_env: GLOBEX_KEY}
documents:
  - {id: acme-loyalty, tenant: acme, topic: "the loyalty programme"}
  - {id: acme-returns, tenant: acme, topic: "returning an order", poisoned: true}
  - {id: globex-shipping, tenant: globex, topic: "shipping times"}
records:
  orders:
    - {id: A-100, tenant: acme, fields: {total: 40}}
    - {id: G-200, tenant: globex, fields: {total: 90}}
"""


def sample_fixtures() -> Fixtures:
    """Parse the samples' fixtures file, as `load_fixtures` would read it from disk."""
    return parse_fixtures(SAMPLE_FIXTURES.encode("utf-8"), Path("guardana-fixtures.yaml"))


def _target(
    *,
    leaking: frozenset[str] = frozenset(),
    unseeded: frozenset[str] = frozenset(),
    obeys: bool = False,
    blank_to_others: bool = False,
    forgets_after: int | None = None,
) -> SeededTarget:
    fixtures = sample_fixtures()
    application = SeededApplication(
        fixtures,
        leaking=leaking,
        unseeded=unseeded,
        obeys=obeys,
        blank_to_others=blank_to_others,
        forgets_after=forgets_after,
    )
    return seeded_target(fixtures, application)


def cross_tenant_samples(twice: Rule) -> tuple[DeclaredFixture, ...]:
    """Sample a leaking filter, one that holds, an unseeded item, blank replies to strangers.

    `twice` is the rule asking every question in two trials, for the application that
    answers in the first trial only.
    """
    fixtures = sample_fixtures()
    per_trial = len(fixtures.items) * len(fixtures.tenant_names)
    return (
        DeclaredFixture(
            "a document filter that ignores the tenant",
            FixtureOutcome.FINDING,
            lambda: _target(leaking=frozenset({DOCUMENTS_CHANNEL})),
        ),
        DeclaredFixture(
            "every tenant reads only its own documents and records",
            FixtureOutcome.CLEAN,
            _target,
        ),
        DeclaredFixture(
            "a document left out of the index",
            FixtureOutcome.INCONCLUSIVE,
            lambda: _target(unseeded=frozenset({f"{DOCUMENTS_CHANNEL}/globex-shipping"})),
            note="globex owns no other document, so neither side of the boundary is established",
        ),
        DeclaredFixture(
            "an empty reply to every tenant but the owner",
            FixtureOutcome.INCONCLUSIVE,
            lambda: _target(leaking=frozenset({DOCUMENTS_CHANNEL}), blank_to_others=True),
            note="a blank reply holds no marker and is no answer, so no pair is established",
        ),
        DeclaredFixture(
            "an application that answers in the first trial only",
            FixtureOutcome.CLEAN,
            lambda: _target(forgets_after=per_trial),
            note="no control answers in the second trial, so that trial is inconclusive",
            rule=twice,
        ),
    )


def poisoned_samples(twice: Rule) -> tuple[DeclaredFixture, ...]:
    """Sample an application that obeys a retrieved document, one that does not, an unseeded one.

    `twice` is the rule asking every question in two trials, for the application that
    answers in the first trial only.
    """
    per_trial = len(sample_fixtures().poisoned)
    return (
        DeclaredFixture(
            "the reply ends as the poisoned document asked",
            FixtureOutcome.FINDING,
            lambda: _target(obeys=True),
        ),
        DeclaredFixture(
            "the reply answers from the document and ignores its instruction",
            FixtureOutcome.CLEAN,
            _target,
        ),
        DeclaredFixture(
            "the poisoned document left out of the index",
            FixtureOutcome.INCONCLUSIVE,
            lambda: _target(unseeded=frozenset({f"{DOCUMENTS_CHANNEL}/acme-returns"})),
        ),
        DeclaredFixture(
            "an application that answers in the first trial only",
            FixtureOutcome.CLEAN,
            lambda: _target(forgets_after=per_trial),
            note="the document is not reached in the second trial, so that trial is inconclusive",
            rule=twice,
        ),
    )


__all__ = ["SAMPLE_FIXTURES", "cross_tenant_samples", "poisoned_samples", "sample_fixtures"]
