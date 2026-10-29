"""The dashboard's browser-side defences: its Content-Security-Policy and its escaping.

Submitted findings are attacker-influenced text, and the page renders them. The
policy forbids every script but the page's own, and the static check below proves,
without a browser, that every value the page's JavaScript splices into HTML is
escaped first.
"""

import base64
import hashlib
import re
from dataclasses import dataclass, field

from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.dashboard import render_dashboard
from guardana.server.store import InMemoryStore

_OK = 200

_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script\b[^>]*>", re.DOTALL | re.IGNORECASE)
_STYLE = re.compile(r"<style\b[^>]*>(.*?)</style\b[^>]*>", re.DOTALL | re.IGNORECASE)

_PAYLOADS = (
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
)


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), dashboard=True, allow_unauthenticated=True))


def _directives(policy: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for directive in policy.split(";"):
        name, *sources = directive.split()
        assert name not in parsed, f"directive {name} appears twice"
        parsed[name] = sources
    return parsed


def _hash_source(text: str) -> str:
    digest = base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
    return f"'sha256-{digest}'"


def test_the_dashboard_page_carries_a_content_security_policy() -> None:
    response = _client().get("/")

    assert response.status_code == _OK
    policy = _directives(response.headers["content-security-policy"])
    assert policy["default-src"] == ["'none'"]
    assert policy["connect-src"] == ["'self'"]
    assert policy["img-src"] == ["'self'", "data:"]
    assert policy["base-uri"] == ["'none'"]
    assert policy["form-action"] == ["'self'"]
    assert policy["frame-ancestors"] == ["'none'"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_scripts_run_only_by_the_hash_of_the_script_actually_served() -> None:
    response = _client().get("/")
    policy = _directives(response.headers["content-security-policy"])
    served = _SCRIPT.findall(response.text)

    assert len(served) == 1
    assert policy["script-src"] == [_hash_source(served[0])]


def test_styles_are_allowed_by_hash_and_never_inline() -> None:
    response = _client().get("/")
    policy = _directives(response.headers["content-security-policy"])
    served = _STYLE.findall(response.text)

    assert len(served) == 1
    assert policy["style-src"] == [_hash_source(served[0])]
    # Under that policy a `style` attribute is dropped by the browser, so the page
    # must not depend on one, in its markup or in what its script builds.
    assert not re.search(r"\sstyle\s*=", response.text)


def test_no_directive_relaxes_to_inline_or_eval() -> None:
    policy = _client().get("/").headers["content-security-policy"]

    for relaxation in ("'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*", "http:"):
        assert relaxation not in policy.split()


def test_the_hash_follows_the_refresh_interval_written_into_the_script() -> None:
    fast = TestClient(
        create_app(
            store=InMemoryStore(), dashboard=True, allow_unauthenticated=True, refresh_seconds=5
        )
    ).get("/")
    slow = TestClient(
        create_app(
            store=InMemoryStore(), dashboard=True, allow_unauthenticated=True, refresh_seconds=50
        )
    ).get("/")

    for response in (fast, slow):
        policy = _directives(response.headers["content-security-policy"])
        assert policy["script-src"] == [_hash_source(_SCRIPT.findall(response.text)[0])]
    assert fast.headers["content-security-policy"] != slow.headers["content-security-policy"]


def test_the_page_carries_no_inline_event_handler_or_url_built_from_data() -> None:
    page = render_dashboard(30)

    assert not re.search(r"\son[a-z]+\s*=", page)
    for template in _scan(_script_of(page)).templates:
        for literal in template.literals:
            assert not re.search(r"\s(href|src|action|formaction)\s*=", literal), literal


def test_a_crafted_finding_reaches_the_api_as_data_and_never_the_page() -> None:
    client = _client()
    envelope = {
        "schema_version": 2,
        "source": _PAYLOADS[0],
        "findings": [
            {
                "rule_id": _PAYLOADS[1],
                "severity": "HIGH",
                "title": _PAYLOADS[2],
                "target_ref": _PAYLOADS[1],
                "evidence": {"summary": _PAYLOADS[0], "detail": _PAYLOADS[2]},
            }
        ],
        "unverified": [],
    }
    assert client.post("/findings", json=envelope).status_code == _OK

    listed = client.get("/findings")
    stats = client.get("/stats")
    page = client.get("/")

    assert listed.headers["content-type"].startswith("application/json")
    stored = listed.json()[0]
    assert stored["source"] == _PAYLOADS[0]
    finding = stored["findings"][0]
    assert (finding["rule_id"], finding["title"]) == (_PAYLOADS[1], _PAYLOADS[2])
    assert finding["evidence"] == {"summary": _PAYLOADS[0], "detail": _PAYLOADS[2]}
    assert stats.headers["content-type"].startswith("application/json")
    assert stats.json()["by_source"][0]["source"] == _PAYLOADS[0]
    for payload in _PAYLOADS:
        assert payload not in page.text
    assert "alert(1)" not in page.text


def test_every_value_spliced_into_a_template_by_the_page_script_is_escaped() -> None:
    """Markup is built only in template literals, and nothing raw reaches one.

    Three properties, together exact for this script: no quoted string carries a
    tag, every `${...}` is escaped or computed, and no bare value is joined onto a
    template with `+`.
    """
    scan = _scan(_script_of(render_dashboard(30)))
    expressions = [expression for template in scan.templates for expression in template.expressions]

    assert [expression for expression in expressions if not _is_safe(expression)] == []
    assert [text for text in scan.strings if _TAG.search(text)] == []
    assert _raw_concatenations(scan.skeleton) == []
    # Guards against a parser that silently finds nothing: the page builds its
    # rows, pills and chart from templates, and those are where data goes.
    assert len(scan.templates) >= 30
    assert "esc(r.source)" in expressions
    assert "esc(ev.summary)" in expressions


def test_every_value_assigned_to_an_html_sink_is_a_template_or_a_helpers_markup() -> None:
    """What reaches `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `fillBars` is covered.

    A raw value assigned to a sink holds no template, no tagged string and no `+`, so the
    template check alone never sees it.
    """
    scan = _scan(_script_of(render_dashboard(30)))

    assert _unsafe_sink_values(scan.skeleton) == []
    assert [
        expression
        for template in scan.templates
        for expression in template.expressions
        if _SINK_NAME.search(expression)
    ] == []
    # Guards against a parser that silently finds nothing: the page fills nine boxes
    # through `innerHTML` and two through `fillBars`.
    assert len(_sink_values(scan.skeleton)) >= 11


def test_the_sink_check_flags_a_raw_value_assigned_to_markup() -> None:
    script = (
        "function fillBars(id, html) { const box = el(id); box.innerHTML = html; }\n"
        'function renderSources(rows) { el("sources").innerHTML = rows[0].source; }\n'
        'el("a").innerHTML = `<td>${esc(r.x)}</td>` + rows.map(r => `<i>${esc(r)}</i>`).join("");\n'
        'el("b").outerHTML = ok ? `<b></b>` : ev.detail;\n'
        'box.insertAdjacentHTML("beforeend", f.title);\n'
        'fillBars("rules", r.name);\n'
        'fillBars("sev", any ? SEVS.map(s => barRow(s, 1, 2, "x")).join("") : `<p></p>`);\n'
        'el("c").innerHTML += items.map(f => { const t = g.map(x => { return x; }); '
        "return f.raw; })"
        '.join("");\n'
        'el("d").innerHTML = tile(n, "l") + sevPill(s) + "plain";\n'
        'el("e").innerHTML = (`<b>${esc(r.y)}</b>`);\n'
        'el("f").innerHTML = html;\n'
    )

    flagged = _unsafe_sink_values(_scan(script).skeleton)

    assert flagged == ["rows[0].source", "ev.detail", "f.title", "r.name", "f.raw", "html"]


def test_the_escaping_check_flags_a_raw_value_in_a_template() -> None:
    script = (
        "const a = `<td>${r.source}</td>`;\n"
        'const b = `<td title="${esc(r.x) + r.y}">${esc(r.z)}</td>`;\n'
        "const c = `<p>${esc(f.title)}</p>`;\n"
        "const d = x / 2, e = /[<\"']/g;\n"
        "const f = `plain ${r.plain}`;\n"
        'const g = `${sevPill(s)}${W}${n ? " on" : ""}${x(i).toFixed(1)}`;\n'
    )

    templates = _scan(script).templates
    flagged = [
        expression
        for template in templates
        for expression in template.expressions
        if not _is_safe(expression)
    ]

    assert flagged == ["r.source", "esc(r.x) + r.y", "r.plain"]


def test_the_escaping_check_flags_markup_outside_a_template() -> None:
    script = (
        'const a = "<td>" + esc(r.x) + "</td>";\n'
        "const b = `<td>` + r.source + `</td>`;\n"
        "const c = `<b>` + tile(r.y) + `</b>`;\n"
        'const d = {"<": "&lt;"};\n'
    )

    scan = _scan(script)

    assert [text for text in scan.strings if _TAG.search(text)] == ["<td>", "</td>"]
    assert _raw_concatenations(scan.skeleton) == ["r.source"]


def test_the_escaping_check_reads_nested_templates_strings_and_regexes() -> None:
    script = (
        "const re = /^guardana\\./;\n"
        "// a comment with a ` backtick\n"
        'const s = "a `quoted` string";\n'
        'const t = `<b>${ok ? `<i>${r.raw}</i>` : ""}</b>`;\n'
    )

    scan = _scan(script)

    assert [template.expressions for template in scan.templates] == [
        ['ok ? `<i>${r.raw}</i>` : ""'],
        ["r.raw"],
    ]
    assert scan.strings == ["a `quoted` string", ""]
    assert not _is_safe(scan.templates[0].expressions[0])


@dataclass
class _Template:
    """One JavaScript template literal: its literal text and its `${...}` expressions."""

    literals: list[str] = field(default_factory=list)
    expressions: list[str] = field(default_factory=list)


@dataclass
class _Scan:
    """What a walk over a script found.

    `skeleton` is the top-level code with every template, quoted string and regular
    expression replaced by a placeholder no identifier can contain, so operators
    around them can be read with a pattern.
    """

    templates: list[_Template] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    skeleton: list[str] = field(default_factory=list)


def _script_of(page: str) -> str:
    scripts = _SCRIPT.findall(page)
    assert len(scripts) == 1
    return str(scripts[0])


def _scan(script: str) -> _Scan:
    scan = _Scan()
    _scan_code(script, 0, scan, inside_expression=False)
    return scan


_REGEX_MAY_FOLLOW = set("(,=:[!&|?{};+-*%<>~^") | {""}
_TEMPLATE, _STRING, _REGEX = "\x01", "\x02", "\x03"


def _scan_code(source: str, start: int, scan: _Scan, *, inside_expression: bool) -> int:
    """Walk JavaScript code until the end, or the `}` closing a `${...}`.

    Strings, comments and regular-expression literals are skipped whole, so a quote
    or backtick inside them is not mistaken for the start of a template.
    """
    depth = 0
    index = start
    previous = ""
    while index < len(source):
        after_comment = _skip_comment(source, index)
        if after_comment is not None:
            index = after_comment
            continue
        char = source[index]
        emitted = char
        if char in "\"'":
            end = _skip_string(source, index)
            scan.strings.append(source[index + 1 : end - 1])
            index, emitted = end, _STRING
        elif char == "`":
            index, emitted = _scan_template(source, index, scan), _TEMPLATE
        elif char == "/" and previous in _REGEX_MAY_FOLLOW:
            index, emitted = _skip_regex(source, index), _REGEX
        elif char == "}" and inside_expression and depth == 0:
            return index
        else:
            depth += {"{": 1, "}": -1}.get(char, 0)
            index += 1
        if not inside_expression:
            scan.skeleton.append(emitted)
        if not char.isspace():
            previous = emitted
    if inside_expression:
        msg = "unterminated ${...} in the dashboard script"
        raise ValueError(msg)
    return index


def _skip_comment(source: str, start: int) -> int | None:
    if source.startswith("//", start):
        newline = source.find("\n", start)
        return len(source) if newline < 0 else newline
    if source.startswith("/*", start):
        return source.index("*/", start) + 2
    return None


def _skip_string(source: str, start: int) -> int:
    quote = source[start]
    index = start + 1
    while source[index] != quote:
        index += 2 if source[index] == "\\" else 1
    return index + 1


def _skip_regex(source: str, start: int) -> int:
    index = start + 1
    in_class = False
    while in_class or source[index] != "/":
        if source[index] == "\\":
            index += 1
        elif source[index] == "[":
            in_class = True
        elif source[index] == "]":
            in_class = False
        index += 1
    return index + 1


def _scan_template(source: str, start: int, scan: _Scan) -> int:
    template = _Template()
    scan.templates.append(template)
    index = start + 1
    literal_start = index
    while source[index] != "`":
        if source[index] == "\\":
            index += 2
        elif source.startswith("${", index):
            template.literals.append(source[literal_start:index])
            close = _scan_code(source, index + 2, scan, inside_expression=True)
            template.expressions.append(source[index + 2 : close].strip())
            index = literal_start = close + 1
        else:
            index += 1
    template.literals.append(source[literal_start:index])
    return index + 1


# Calls and locals whose value is markup built from templates this same check
# covers, or text made only of numbers the script computed.
_ESCAPED_HELPERS = frozenset({"esc", "sevPill", "dots", "path"})
_COMPUTED_LOCALS = frozenset({"w", "W", "H", "det", "tax"})
_TO_FIXED = re.compile(r"[\w.()\[\]]+\.toFixed\(\d+\)")
_LITERAL_CHOICE = re.compile(r"""[^?`$]+\?\s*"[^"<>&]*"\s*:\s*"[^"<>&]*\"""")
_TAG = re.compile(r"<[a-zA-Z/!]")
_OPERAND = r"[A-Za-z_$][\w$]*+(?:\.[A-Za-z_$][\w$]*+|\[[^\]]*\])*+"
_TEMPLATE_THEN_RAW = re.compile(rf"{_TEMPLATE}\s*+\+\s*+({_OPERAND})\s*+(?![(\w$.\[])")
_RAW_THEN_TEMPLATE = re.compile(rf"(?<![\w$.\])])({_OPERAND})\s*+\+\s*+{_TEMPLATE}")


def _is_safe(expression: str) -> bool:
    if expression in _COMPUTED_LOCALS:
        return True
    if _TO_FIXED.fullmatch(expression) or _LITERAL_CHOICE.fullmatch(expression):
        return True
    call = re.match(r"(\w+)\(", expression)
    return (
        call is not None
        and call.group(1) in _ESCAPED_HELPERS
        and _closing_paren(expression, call.end() - 1) == len(expression) - 1
    )


def _raw_concatenations(skeleton: list[str]) -> list[str]:
    """Bare variables or members joined with `+` directly onto a template literal."""
    code = "".join(skeleton)
    spans = {
        match.span(1): match.group(1)
        for pattern in (_TEMPLATE_THEN_RAW, _RAW_THEN_TEMPLATE)
        for match in pattern.finditer(code)
    }
    return [spans[span] for span in sorted(spans)]


# Calls whose value is markup built only from templates the template check covers.
_MARKUP_HELPERS = _ESCAPED_HELPERS | {"barRow", "tile"}
_SINK_NAME = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|fillBars")
_SINK_ASSIGNMENT = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)")
_SINK_CALLS = {"insertAdjacentHTML": 1, "fillBars": 1}
"""Each call that writes markup, with the index of the argument holding it."""
_SINK_CALL = re.compile(r"(?<![\w$])(insertAdjacentHTML|fillBars)\s*\(")
_ARROW = re.compile(r"\s*(?:[A-Za-z_$][\w$]*|\([^()]*\))\s*=>(.*)", re.DOTALL)
_OPENING, _CLOSING = "([{", ")]}"


def _sink_values(skeleton: list[str]) -> list[str]:
    """The value written by every HTML sink in top-level code, in source order.

    A sink inside a function that forwards one of its parameters to it, as `fillBars`
    does, is left out when it writes that parameter: its callers are sinks themselves.
    """
    code = "".join(skeleton)
    forwarded = _forwarded_parameters(code)
    values = [
        (match.start(), _until_statement_end(code, match.end()).strip())
        for match in _SINK_ASSIGNMENT.finditer(code)
    ]
    for match in _SINK_CALL.finditer(code):
        if code[: match.start()].rstrip().endswith("function"):
            continue
        opening = match.end() - 1
        arguments = _split_top_level(code[opening + 1 : _matching(code, opening)], ",")
        index = _SINK_CALLS[match.group(1)]
        values.append((match.start(), arguments[index].strip() if index < len(arguments) else ""))
    return [
        value
        for start, value in sorted(values)
        if not any(low <= start < high and value == name for low, high, name in forwarded)
    ]


def _unsafe_sink_values(skeleton: list[str]) -> list[str]:
    """The parts of every sink's value that are neither a template nor a helper's markup."""
    return [part for value in _sink_values(skeleton) for part in _unsafe_markup(value)]


def _forwarded_parameters(code: str) -> list[tuple[int, int, str]]:
    """The body span of every sink function the script defines, with its markup parameter."""
    spans: list[tuple[int, int, str]] = []
    for name, index in _SINK_CALLS.items():
        for match in re.finditer(rf"function\s+{name}\s*\(([^)]*)\)\s*\{{", code):
            parameters = [parameter.strip() for parameter in match.group(1).split(",")]
            if index < len(parameters):
                spans.append((match.end(), _matching(code, match.end() - 1), parameters[index]))
    return spans


def _unsafe_markup(value: str) -> list[str]:
    """Return what in `value` could carry raw text into markup, readable; empty when nothing."""
    value = _unwrapped(value.strip())
    choice = _ternary(value)
    if choice is not None:
        return _unsafe_markup(choice[0]) + _unsafe_markup(choice[1])
    terms = _split_top_level(value, "+")
    if len(terms) > 1:
        return [part for term in terms for part in _unsafe_markup(term)]
    if value in {_TEMPLATE, _STRING}:
        return []
    call = re.match(r"([A-Za-z_$][\w$]*)\s*\(", value)
    if (
        call is not None
        and call.group(1) in _MARKUP_HELPERS
        and _matching(value, call.end() - 1) == len(value) - 1
    ):
        return []
    mapped = _mapped_markup(value)
    if mapped is not None:
        return mapped
    return [value.replace(_TEMPLATE, "`…`").replace(_STRING, '"…"').replace(_REGEX, "/…/")]


def _mapped_markup(value: str) -> list[str] | None:
    """Check `items.map(callback).join("…")` by what the callback returns; None for other shapes."""
    found = _top_level_find(value, ".map(")
    if found < 0:
        return None
    opening = found + len(".map")
    closing = _matching(value, opening)
    if closing < 0 or not re.fullmatch(rf"\.join\(\s*{_STRING}\s*\)", value[closing + 1 :].strip()):
        return None
    arrow = _ARROW.fullmatch(value[opening + 1 : closing])
    if arrow is None:
        return None
    body = arrow.group(1).strip()
    if not (body.startswith("{") and _matching(body, 0) == len(body) - 1):
        return _unsafe_markup(body)
    returned = _returned(body[1:-1])
    if not returned:
        return [value]
    return [part for expression in returned for part in _unsafe_markup(expression)]


def _returned(block: str) -> list[str]:
    """The expressions a function body returns, not counting functions nested in it."""
    found: list[str] = []
    depth = 0
    for index, char in enumerate(block):
        if depth == 0 and re.match(r"return\b", block[index:]):
            before = block[index - 1] if index else " "
            if not (before.isalnum() or before in "_$."):
                found.append(_until_statement_end(block, index + len("return")).strip())
        depth += (char in _OPENING) - (char in _CLOSING)
    return found


def _ternary(value: str) -> tuple[str, str] | None:
    """Split `condition ? a : b` at the top level into its two branches; None for another shape."""
    depth = 0
    question = -1
    nested = 0
    for index, char in enumerate(value):
        depth += (char in _OPENING) - (char in _CLOSING)
        if depth != 0:
            continue
        if char == "?" and value[index + 1 : index + 2] not in {".", "?"}:
            if question < 0:
                question = index
            else:
                nested += 1
        elif char == ":" and question >= 0:
            if nested == 0:
                return value[question + 1 : index], value[index + 1 :]
            nested -= 1
    return None


def _unwrapped(value: str) -> str:
    while value.startswith("(") and _matching(value, 0) == len(value) - 1:
        value = value[1:-1].strip()
    return value


def _split_top_level(value: str, separator: str) -> list[str]:
    """Split `value` at every `separator` outside brackets; `++` and `+=` are not a split."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(value):
        depth += (char in _OPENING) - (char in _CLOSING)
        if depth != 0 or char != separator:
            continue
        if separator == "+" and "+" in (value[index - 1 : index], value[index + 1 : index + 2]):
            continue
        if value[index + 1 : index + 2] == "=":
            continue
        parts.append(value[start:index])
        start = index + 1
    parts.append(value[start:])
    return parts


def _top_level_find(value: str, needle: str) -> int:
    depth = 0
    for index, char in enumerate(value):
        if depth == 0 and value.startswith(needle, index):
            return index
        depth += (char in _OPENING) - (char in _CLOSING)
    return -1


def _until_statement_end(code: str, start: int) -> str:
    """The text from `start` to the `;` ending its statement, or the bracket closing its block."""
    depth = 0
    for index in range(start, len(code)):
        char = code[index]
        if char in _CLOSING and depth == 0:
            return code[start:index]
        if char == ";" and depth == 0:
            return code[start:index]
        depth += (char in _OPENING) - (char in _CLOSING)
    return code[start:]


def _matching(code: str, opening: int) -> int:
    """The index of the bracket closing the one at `opening`, or -1 when it never closes."""
    depth = 0
    for index in range(opening, len(code)):
        depth += (code[index] in _OPENING) - (code[index] in _CLOSING)
        if depth == 0:
            return index
    return -1


def _closing_paren(expression: str, opening: int) -> int:
    depth = 0
    index = opening
    while index < len(expression):
        if expression[index] in "\"'":
            index = _skip_string(expression, index)
            continue
        if expression[index] == "`":
            return -1
        depth += {"(": 1, ")": -1}.get(expression[index], 0)
        if depth == 0:
            return index
        index += 1
    return -1
