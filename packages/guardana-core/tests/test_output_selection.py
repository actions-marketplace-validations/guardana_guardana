"""An installed output is selected by its entry-point name, and refused before it is imported.

Reserved names, unknown names, collisions and trust refusals are decided from metadata
alone, so none of them imports a module; a provider or a `prepare` that fails, even by
calling `sys.exit`, is `broken` rather than the end of the command. Distributions are
written as `.dist-info` directories on `sys.path`, so the real metadata finder reads them.
"""

import sys
from collections.abc import Iterator, Sequence
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest
from _fake_distribution import FakeModule, FakeSite
from _output_modules import (
    EXITING_IMPORT,
    EXITING_PREPARE,
    EXITING_PROVIDER,
    FAILING_IMPORT,
    INTERRUPTED_PROVIDER,
    MISNAMED_PROVIDER,
    NO_DELIVERER_PREPARE,
    RAISING_PREPARE,
    RAISING_PROVIDER,
    RECORDING_RENDERER,
    RECORDING_REPORTER,
    SECRET_DESTINATION_PREPARE,
    UNWITHHELD_DESTINATION_PREPARE,
    WRONG_TYPE_PROVIDER,
    body,
)
from guardana.core import output as output_module
from guardana.core.entrypoints import (
    GROUPS,
    OUTPUT_GROUPS,
    RENDERER_GROUP,
    REPORTER_GROUP,
    InstalledEntryPoint,
    installed_entry_points,
)
from guardana.core.origin import Origin
from guardana.core.output import (
    Delivery,
    DeliveryStatus,
    OutputSelectionError,
    OutputSelectionKind,
    discover_outputs,
    format_delivery_line,
    is_output_name,
    select_renderer,
    select_reporter,
)
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry

_DIST = "acme-guardana-outputs"
_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)
_ADMITTED = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({_DIST}))
_ALL = PluginTrust(mode=PluginMode.ALL)
DELIVERED = DeliveryStatus.DELIVERED


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _install(  # noqa: PLR0913 — one fake install, every coordinate keyword-only
    site: FakeSite,
    template: str,
    *,
    group: str = RENDERER_GROUP,
    name: str = "acme-table",
    distribution: str = _DIST,
    version: str = "1.0",
) -> FakeModule:
    module = site.module(body(template, name))
    site.distribution(distribution, (group, name, module.name), version=version)
    return module


def _not_imported(*modules: FakeModule) -> bool:
    return all(m.name not in sys.modules and not m.marker.exists() for m in modules)


def _refusal(kind: OutputSelectionKind, raised: pytest.ExceptionInfo[OutputSelectionError]) -> str:
    assert raised.value.kind is kind, raised.value.message
    assert str(raised.value) == raised.value.message
    return raised.value.message


@pytest.mark.parametrize("name", ["human", "json", "sarif", "junit", "guardana", "guardana-csv"])
def test_a_reserved_format_name_is_refused_even_when_installed(site: FakeSite, name: str) -> None:
    module = _install(site, RECORDING_RENDERER, name=name)

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer(name, _ALL)

    message = _refusal(OutputSelectionKind.RESERVED, raised)
    assert message == f"{name} is a built-in format name, so no installed format can use it"
    assert _not_imported(module)


@pytest.mark.parametrize("name", ["server", "http", "https", "guardana-hook"])
def test_a_reserved_reporter_name_is_refused(site: FakeSite, name: str) -> None:
    module = _install(site, RECORDING_REPORTER, group=REPORTER_GROUP, name=name)

    with pytest.raises(OutputSelectionError) as raised:
        select_reporter(name, "x", _ALL)

    message = _refusal(OutputSelectionKind.RESERVED, raised)
    assert message == f"{name} is a built-in reporter name, so no installed reporter can use it"
    assert _not_imported(module)


def test_a_reporter_may_use_a_format_name_and_a_format_a_reporter_name(site: FakeSite) -> None:
    table = site.module(body(RECORDING_RENDERER, "server"))
    hook = site.module(body(RECORDING_REPORTER, "json"))
    site.distribution(
        _DIST, (RENDERER_GROUP, "server", table.name), (REPORTER_GROUP, "json", hook.name)
    )

    assert select_renderer("server", _ADMITTED).name == "server"
    assert select_reporter("json", "x", _ADMITTED).name == "json"


@pytest.mark.parametrize("name", ["Acme", "1acme", "acme_table", "acme.table", "", "a" * 41])
def test_a_name_outside_the_pattern_is_unknown(name: str) -> None:
    assert not is_output_name(name)

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer(name, _ALL)

    _refusal(OutputSelectionKind.UNKNOWN, raised)


def test_the_longest_name_allowed_has_forty_characters() -> None:
    assert is_output_name("a" * 40)


def test_an_unknown_format_names_the_built_ins_and_what_is_installed(site: FakeSite) -> None:
    module = _install(site, RECORDING_RENDERER)

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-tabel", _ADMITTED)

    assert _refusal(OutputSelectionKind.UNKNOWN, raised) == (
        "the format acme-tabel is not installed; built-in: human, json, sarif, junit; "
        "installed: acme-table (admitted)"
    )
    assert _not_imported(module)


def test_an_unknown_reporter_names_the_collector_forms_and_what_is_installed(
    site: FakeSite,
) -> None:
    _install(site, RECORDING_REPORTER, group=REPORTER_GROUP, name="acme-webhook")

    with pytest.raises(OutputSelectionError) as raised:
        select_reporter("acme-hook", "x", _BUILTINS)

    assert _refusal(OutputSelectionKind.UNKNOWN, raised) == (
        "the reporter acme-hook is not installed; built-in: server://URL or an http(s) "
        "collector URL; installed: acme-webhook (refused)"
    )


def test_an_unknown_name_with_nothing_installed_says_so() -> None:
    with pytest.raises(OutputSelectionError) as raised:
        select_reporter("acme-hook", "x", _BUILTINS)

    assert _refusal(OutputSelectionKind.UNKNOWN, raised).endswith("; installed: none")


def test_a_format_installed_as_a_reporter_is_unknown_as_a_format(site: FakeSite) -> None:
    module = _install(site, RECORDING_REPORTER, group=REPORTER_GROUP)

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-table", _ADMITTED)

    _refusal(OutputSelectionKind.UNKNOWN, raised)
    assert _not_imported(module)


def test_two_distributions_installing_one_name_collide_and_neither_is_imported(
    site: FakeSite,
) -> None:
    first = _install(site, RECORDING_RENDERER, distribution="acme-a")
    second = _install(site, RECORDING_RENDERER, distribution="acme-b", version="2.0")

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-table", _ALL)

    assert _refusal(OutputSelectionKind.COLLISION, raised) == (
        "the format acme-table is installed by 2 distributions (acme-a 1.0, acme-b 2.0), "
        "so neither is used"
    )
    assert set(raised.value.distributions) == {"acme-a", "acme-b"}
    assert _not_imported(first, second)


def _entry(
    group: str,
    module: FakeModule,
    *,
    distribution: str | None = _DIST,
    version: str | None = "1.0",
    attribute: str = "provide",
) -> InstalledEntryPoint:
    value = f"{module.name}:{attribute}"
    return InstalledEntryPoint(
        group=group,
        name="acme-table",
        value=value,
        module=module.name,
        distribution=distribution,
        version=version,
        entry_point=EntryPoint(name="acme-table", value=value, group=group),
    )


def _listed(monkeypatch: pytest.MonkeyPatch, *entries: InstalledEntryPoint) -> None:
    """List `entries` as installed, past the de-duplication `importlib.metadata` applies."""

    def listed(groups: Sequence[str] = GROUPS) -> tuple[InstalledEntryPoint, ...]:
        return tuple(entry for entry in entries if entry.group in groups)

    monkeypatch.setattr(output_module, "installed_entry_points", listed)


def _differing(difference: str, module: FakeModule) -> tuple[InstalledEntryPoint, ...]:
    if difference == "version":
        return _entry(RENDERER_GROUP, module), _entry(RENDERER_GROUP, module, version="1.1")
    if difference == "value":
        return _entry(RENDERER_GROUP, module), _entry(RENDERER_GROUP, module, attribute="again")
    if difference == "distribution":
        return _entry(RENDERER_GROUP, module), _entry(
            RENDERER_GROUP, module, distribution="other-outputs"
        )
    return tuple(_entry(RENDERER_GROUP, module, distribution=None, version=None) for _ in range(2))


@pytest.mark.parametrize("difference", ["version", "value", "distribution", "two-unnamed"])
def test_entry_points_differing_in_distribution_value_or_version_collide(
    site: FakeSite, monkeypatch: pytest.MonkeyPatch, difference: str
) -> None:
    module = site.module(body(RECORDING_RENDERER, "acme-table"))
    _listed(monkeypatch, *_differing(difference, module))

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-table", _ALL)

    _refusal(OutputSelectionKind.COLLISION, raised)
    assert _not_imported(module)


def test_one_distribution_spelled_two_ways_is_one_install(
    site: FakeSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = site.module(body(RECORDING_RENDERER, "acme-table"))
    _listed(
        monkeypatch,
        _entry(RENDERER_GROUP, module, distribution="Acme_Guardana.Outputs"),
        _entry(RENDERER_GROUP, module, distribution="acme-guardana-outputs"),
    )

    assert select_renderer("acme-table", _ADMITTED).origin.distribution == "Acme_Guardana.Outputs"


def test_a_format_trust_does_not_admit_is_refused_and_never_imported(site: FakeSite) -> None:
    module = _install(site, RECORDING_RENDERER, version="0.1.0")

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-table", _BUILTINS)

    assert _refusal(OutputSelectionKind.REFUSED, raised) == (
        "the format acme-table comes from acme-guardana-outputs 0.1.0, which plugin trust "
        "builtins does not admit"
    )
    assert raised.value.distributions == (_DIST,)
    assert _not_imported(module)


@pytest.mark.parametrize("trust", [_BUILTINS, _ADMITTED], ids=["builtins", "allowlist"])
def test_an_output_naming_no_distribution_is_refused(
    site: FakeSite, monkeypatch: pytest.MonkeyPatch, trust: PluginTrust
) -> None:
    module = site.module(body(RECORDING_RENDERER, "acme-table"))
    _listed(monkeypatch, _entry(RENDERER_GROUP, module, distribution=None, version=None))

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-table", trust)

    assert "comes from an unnamed distribution" in _refusal(OutputSelectionKind.REFUSED, raised)
    assert raised.value.distributions == ()
    assert _not_imported(module)


def test_an_admitted_format_is_selected_with_its_origin(site: FakeSite) -> None:
    module = _install(site, RECORDING_RENDERER, version="0.1.0")

    selected = select_renderer("acme-table", _ADMITTED)

    assert selected.name == "acme-table"
    assert selected.spec.name == "acme-table"
    assert selected.origin == Origin(distribution=_DIST, version="0.1.0")
    assert module.marker.exists()


@pytest.mark.parametrize(
    ("template", "reason"),
    [
        (RAISING_PROVIDER, "ValueError: the provider is broken"),
        (EXITING_PROVIDER, "SystemExit: 0"),
        (WRONG_TYPE_PROVIDER, "the provider returned int, not a RendererSpec"),
        (MISNAMED_PROVIDER, "is named 'someone-else', not 'acme-table'"),
        (FAILING_IMPORT, "RuntimeError: this module was imported"),
        (EXITING_IMPORT, "SystemExit: 0"),
    ],
    ids=["raises", "sys-exit", "wrong-type", "misnamed", "import-fails", "import-exits"],
)
def test_a_provider_that_fails_is_broken_never_fatal(
    site: FakeSite, template: str, reason: str
) -> None:
    _install(site, template, version="0.1.0")

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-table", _ADMITTED)

    message = _refusal(OutputSelectionKind.BROKEN, raised)
    assert message.startswith(
        "the format acme-table from acme-guardana-outputs 0.1.0 could not be loaded: "
    )
    assert reason in message


def test_a_provider_interrupted_by_the_operator_propagates(site: FakeSite) -> None:
    _install(site, INTERRUPTED_PROVIDER)

    with pytest.raises(KeyboardInterrupt):
        select_renderer("acme-table", _ADMITTED)


def test_a_broken_reason_is_sanitised(site: FakeSite) -> None:
    module = site.module(
        body(RAISING_PROVIDER, "acme-table").replace(
            '"the provider is broken"', '"line\\x1b[31m one\\nkey AKIA" + "Q" * 16'
        )
    )
    site.distribution(_DIST, (RENDERER_GROUP, "acme-table", module.name))

    with pytest.raises(OutputSelectionError) as raised:
        select_renderer("acme-table", _ADMITTED)

    message = _refusal(OutputSelectionKind.BROKEN, raised)
    assert "AKIA" + "Q" * 16 not in message
    assert "\x1b" not in message
    assert "\n" not in message


def test_an_admitted_reporter_is_prepared_with_its_locator(site: FakeSite) -> None:
    _install(site, RECORDING_REPORTER, group=REPORTER_GROUP, name="acme-webhook")

    prepared = select_reporter("acme-webhook", "env:ACME_WEBHOOK_URL", _ADMITTED)

    assert prepared.name == "acme-webhook"
    assert prepared.destination == "https://hooks.example.invalid"
    assert prepared.origin == Origin(distribution=_DIST, version="1.0")
    assert getattr(prepared.deliverer, "locator", None) == "env:ACME_WEBHOOK_URL"


@pytest.mark.parametrize(
    ("template", "reason"),
    [
        (RAISING_PREPARE, "ValueError: ACME_WEBHOOK_URL is not set"),
        (EXITING_PREPARE, "SystemExit: 0"),
        (NO_DELIVERER_PREPARE, "prepare returned no deliverer"),
    ],
    ids=["raises", "sys-exit", "no-deliverer"],
)
def test_a_prepare_that_fails_is_broken(site: FakeSite, template: str, reason: str) -> None:
    _install(site, template, group=REPORTER_GROUP, name="acme-webhook")

    with pytest.raises(OutputSelectionError) as raised:
        select_reporter("acme-webhook", "x", _ADMITTED)

    message = _refusal(OutputSelectionKind.BROKEN, raised)
    assert message.startswith("the reporter acme-webhook from acme-guardana-outputs 1.0 could not")
    assert reason in message


def test_a_prepared_destination_withholds_what_the_deliverer_sends(site: FakeSite) -> None:
    _install(site, SECRET_DESTINATION_PREPARE, group=REPORTER_GROUP, name="acme-webhook")
    token = "tok" + "e" * 12

    prepared = select_reporter("acme-webhook", f"queue:acme/{token}", _ADMITTED)

    assert token not in prepared.destination
    assert prepared.destination.startswith("queue:acme/")
    assert prepared.secrets == (token,)


@pytest.mark.parametrize(
    ("locator", "shown"),
    [
        (
            "https://ci-bot:s3cr3tPassw0rd@hooks.example.com/services/T0/B0/XoXoSecretPath"
            "?token=abc123",
            "https://hooks.example.com",
        ),
        ("http://hooks.example.com:8443/p#fragment", "http://hooks.example.com:8443"),
        ("https://user@[2001:db8::1]:9000/path", "https://[2001:db8::1]:9000"),
        ("queue:acme-alerts", "queue:acme-alerts"),
    ],
    ids=["credentials-path-query", "port-fragment", "ipv6", "not-a-url"],
)
def test_a_url_destination_is_shown_as_its_scheme_and_host_only(
    site: FakeSite, locator: str, shown: str
) -> None:
    _install(site, UNWITHHELD_DESTINATION_PREPARE, group=REPORTER_GROUP, name="acme-webhook")

    prepared = select_reporter("acme-webhook", locator, _ADMITTED)

    assert prepared.destination == shown
    line = format_delivery_line(prepared.name, prepared.destination, Delivery(DELIVERED))
    assert line == f"delivery: delivered — acme-webhook to {shown}"


def test_selecting_a_format_imports_no_reporter_of_the_same_distribution(site: FakeSite) -> None:
    table = site.module(body(RECORDING_RENDERER, "acme-table"))
    hook = site.module(body(RECORDING_REPORTER, "acme-webhook"))
    site.distribution(
        _DIST,
        (RENDERER_GROUP, "acme-table", table.name),
        (REPORTER_GROUP, "acme-webhook", hook.name),
    )

    select_renderer("acme-table", _ADMITTED)

    assert table.marker.exists()
    assert _not_imported(hook)


def test_a_run_never_lists_or_imports_an_installed_output(site: FakeSite) -> None:
    table = _install(site, FAILING_IMPORT)
    hook = _install(
        site, FAILING_IMPORT, group=REPORTER_GROUP, name="acme-webhook", distribution="acme-hooks"
    )

    registry = Registry.discover(_ALL)

    assert not [ep for ep in installed_entry_points() if ep.group in OUTPUT_GROUPS]
    assert {ep.module for ep in installed_entry_points(OUTPUT_GROUPS)} >= {table.name, hook.name}
    assert not [e for e in registry.load_errors if e.source in {"acme-table", "acme-webhook"}]
    assert _not_imported(table, hook)


def test_the_enumeration_lists_groups_in_the_order_asked() -> None:
    assert installed_entry_points() == installed_entry_points(GROUPS)


def test_discovery_imports_what_it_admits_and_accounts_for_the_rest(site: FakeSite) -> None:
    admitted = _install(site, RECORDING_RENDERER)
    broken = _install(
        site, RAISING_PROVIDER, group=REPORTER_GROUP, name="acme-webhook", distribution="acme-b0"
    )
    refused = _install(site, RECORDING_RENDERER, name="other-table", distribution="other-outputs")
    collided = [
        _install(site, RECORDING_REPORTER, group=REPORTER_GROUP, name="acme-hook", distribution=d)
        for d in ("acme-a", "acme-b")
    ]
    reserved = _install(site, FAILING_IMPORT, name="json", distribution="acme-r")
    trust = PluginTrust(
        mode=PluginMode.ALLOWLIST,
        allowed=frozenset({_DIST, "acme-b0", "acme-a", "acme-b", "acme-r"}),
    )

    found = discover_outputs(trust)

    assert dict(found.renderers) == {"acme-table": Origin(distribution=_DIST, version="1.0")}
    assert dict(found.reporters) == {}
    assert [(ep.name, ep.distribution) for ep in found.refused] == [
        ("other-table", "other-outputs")
    ]
    assert [(ep.name, reason) for ep, reason in found.failed] == [
        ("acme-webhook", "ValueError: the provider is broken")
    ]
    assert dict(found.collisions) == {"reporter:acme-hook": ("acme-a 1.0", "acme-b 1.0")}
    assert admitted.marker.exists()
    assert broken.marker.exists()
    assert _not_imported(refused, reserved, *collided)


def test_discovery_with_nothing_installed_finds_nothing() -> None:
    found = discover_outputs(_ALL)

    assert (found.renderers, found.reporters, found.refused, found.failed, found.collisions) == (
        {},
        {},
        (),
        (),
        {},
    )
