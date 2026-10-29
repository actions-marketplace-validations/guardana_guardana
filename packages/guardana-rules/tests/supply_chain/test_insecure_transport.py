from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.insecure_transport import InsecureTransportRule


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = InsecureTransportRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def test_flags_verify_false(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('https://x', verify=False)\n", encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert findings == [("HIGH", "verify=False disables TLS certificate checks (MITM risk)")]


def test_flags_plaintext_http_download(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('http://weights.example/model.bin')\n", encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    severity, summary = findings[0]
    assert severity == "MEDIUM"
    assert "http://" in summary


def test_flags_plaintext_http_on_from_pretrained(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "m = AutoModel.from_pretrained('http://hub.example/repo')\n", encoding="utf-8"
    )
    assert _findings(tmp_path)


def test_flags_plaintext_http_with_uppercase_scheme(tmp_path: Path) -> None:
    # `HTTP://` is exactly as plaintext as `http://`; a case-sensitive check let it
    # slip past. The scheme is matched case-insensitively.
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('HTTP://weights.example/model.bin')\n", encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "MEDIUM"


def test_https_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('https://weights.example/model.bin')\n", encoding="utf-8"
    )
    assert _findings(tmp_path) == []


def test_localhost_http_is_not_flagged(tmp_path: Path) -> None:
    # Plaintext to localhost/127.0.0.1 is a normal dev setup, not a MITM exposure.
    (tmp_path / "a.py").write_text(
        "import requests\n"
        "requests.get('http://localhost:8000/v1')\n"
        "requests.get('http://127.0.0.1/model')\n",
        encoding="utf-8",
    )
    assert _findings(tmp_path) == []


def test_http_string_outside_a_fetch_call_is_not_flagged(tmp_path: Path) -> None:
    # An http:// literal that is not an argument to a network call (an XML
    # namespace, a plain assignment) is not a download — flagging it would be noise.
    (tmp_path / "a.py").write_text(
        "NS = 'http://www.w3.org/2001/XMLSchema'\nlabel = 'http://example/doc'\n",
        encoding="utf-8",
    )
    assert _findings(tmp_path) == []


def test_verify_true_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import requests\nrequests.get('https://x', verify=True)\n", encoding="utf-8"
    )
    assert _findings(tmp_path) == []


def test_a_syntax_error_is_declined_as_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert [s.split(":")[0] for _, s in _findings(tmp_path)] == ["Python file not scanned"]


def _fetching(tmp_path: Path, url: str) -> list[tuple[str, str]]:
    (tmp_path / "a.py").write_text(f"import requests\nrequests.get({url!r})\n", encoding="utf-8")
    return _findings(tmp_path)


_PLAIN = "http" + "://"


@pytest.mark.parametrize(
    ("url", "host"),
    [
        (_PLAIN + "localhost:secret@attacker.example/w.bin", "attacker.example"),
        (_PLAIN + "localhost@attacker.example/w.bin", "attacker.example"),
        (_PLAIN + "127.0.0.1:8000@attacker.example/w.bin", "attacker.example"),
        (_PLAIN + "user@Attacker.Example:8080/w.bin", "attacker.example"),
        (_PLAIN + "[2001:db8::1]:8080/w.bin", "2001:db8::1"),
        ("HTTP://weights.example/w.bin", "weights.example"),
        ("Http://localhost@weights.example/w.bin", "weights.example"),
    ],
)
def test_a_plaintext_fetch_names_the_host_it_connects_to(
    tmp_path: Path, url: str, host: str
) -> None:
    findings = _fetching(tmp_path, url)

    assert findings == [
        ("MEDIUM", f"plaintext http:// fetch from {host} (weights can be swapped in transit)")
    ]


@pytest.mark.parametrize(
    "url",
    [
        _PLAIN + "[::1/w.bin",
        _PLAIN + "[not-an-address]/w.bin",
        _PLAIN + "/w.bin",
        _PLAIN + "user@/w.bin",
    ],
)
def test_a_plaintext_fetch_whose_host_cannot_be_read_is_reported(tmp_path: Path, url: str) -> None:
    findings = _fetching(tmp_path, url)

    assert [severity for severity, _ in findings] == ["MEDIUM"]
    assert "an unreadable host" in findings[0][1]


@pytest.mark.parametrize(
    "url",
    [
        _PLAIN + "[::1]:8000/v1",
        _PLAIN + "[::1]/v1",
        _PLAIN + "LOCALHOST:8000/v1",
        _PLAIN + "admin:secret@localhost:8000/v1",
        _PLAIN + "attacker.example@127.0.0.1/v1",
        _PLAIN + "0.0.0.0:8000/v1",
        "https://localhost:secret@attacker.example/w.bin",
    ],
)
def test_a_fetch_that_stays_on_this_machine_or_uses_tls_is_not_flagged(
    tmp_path: Path, url: str
) -> None:
    assert _fetching(tmp_path, url) == []
