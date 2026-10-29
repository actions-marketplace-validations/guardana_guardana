"""`acme-webhook`: the run's summary as one signed Standard Webhooks delivery.

`--reporter acme-webhook://https://hooks.example.com/guardana` sends to that URL, and
`--reporter acme-webhook://env:ACME_WEBHOOK_URL` reads it from the variable, so a URL that
carries a token stays out of shell history. `ACME_WEBHOOK_SECRET` (`whsec_<base64>`) keys
the signature. The body carries counts, rule ids, severities and titles: never evidence,
a prompt or a reply. `prepare` sends nothing; `deliver` connects straight to the
destination, whatever `HTTP_PROXY` or `HTTPS_PROXY` say, makes at most three attempts
within 25 seconds and says what became of them.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields
from email.message import Message
from http.client import HTTPException
from typing import IO
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

from guardana.core.assessment import AssessmentStatus
from guardana.core.output import Delivery, DeliveryStatus, ReporterRequest, ReporterSpec
from guardana.core.report import ScanResult
from guardana.core.severity import Severity
from guardana.core.verify import Verification

NAME = "acme-webhook"
SECRET_VARIABLE = "ACME_WEBHOOK_SECRET"  # noqa: S105 — the variable's name, not its value
EVENT_TYPE = "run.completed"

MAX_BODY_BYTES = 20480
MAX_FINDINGS = 50
MAX_ATTEMPTS = 3
DEADLINE_SECONDS = 25.0
ATTEMPT_TIMEOUT_SECONDS = 10.0
BACKOFF_SECONDS = (1.0, 2.0)
MAX_RESPONSE_BYTES = 64 * 1024

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_ENV_PREFIX = "env:"
_SECRET_PREFIX = "whsec_"  # noqa: S105 — the format's prefix, not a secret
_SECONDS = re.compile(r"[0-9]+")
_GONE = 410
_TIMEOUT = 408
_TOO_MANY = 429
_SEVERITIES = tuple(sorted(Severity, reverse=True))
_CASE_KEYS = ("passed", "failed", "measured", "inconclusive", "error", "skipped")
_SUITE_KEYS = ("pass", "fail", "inconclusive")


class WebhookRefusedError(ValueError):
    """A reporter request `prepare` refuses; its message never repeats the URL."""


def spec() -> ReporterSpec:
    """Return the `acme-webhook` reporter."""
    return ReporterSpec(
        name=NAME,
        summary="the run's summary as a signed Standard Webhooks delivery",
        prepare=prepare,
    )


def prepare(
    request: ReporterRequest,
    *,
    environ: Mapping[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    now: Callable[[], float] = time.time,
) -> "Webhook":
    """Check the destination and the secret and return a deliverer; sends nothing.

    Raises `WebhookRefusedError` for an unset variable, a destination that is not
    `https` (loopback hosts may use `http`), userinfo in the URL, or a secret that is
    unset or not `whsec_` followed by base64.
    """
    env = os.environ if environ is None else environ
    url = _destination_url(request.locator, env)
    destination = _display(url)
    secret = env.get(SECRET_VARIABLE, "")
    key = _signing_key(secret)
    return Webhook(
        destination=destination,
        url=url,
        secret=secret,
        key=key,
        sleep=sleep,
        monotonic=monotonic,
        now=now,
    )


def _destination_url(locator: str, env: Mapping[str, str]) -> str:
    if locator.startswith(_ENV_PREFIX):
        variable = locator[len(_ENV_PREFIX) :]
        url = env.get(variable, "")
        if not url:
            raise WebhookRefusedError(f"{variable} is not set, so there is no destination")
        return url
    if not locator:
        raise WebhookRefusedError("no destination: give a URL or env:NAME after acme-webhook://")
    return locator


def _display(url: str) -> str:
    """Return `scheme://host[:port]`, refusing a URL this reporter will not send to."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise WebhookRefusedError("the destination is not a URL") from None
    host = parts.hostname
    if parts.scheme not in {"https", "http"} or not host:
        raise WebhookRefusedError("the destination must be an https:// URL")
    if parts.scheme == "http" and host not in _LOOPBACK:
        raise WebhookRefusedError(
            "the destination must be https; plain http is accepted only for localhost"
        )
    if parts.username is not None or parts.password is not None:
        raise WebhookRefusedError("the destination must not carry credentials before its host")
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + ("" if port is None else f":{port}")


def _signing_key(secret: str) -> bytes:
    if not secret:
        raise WebhookRefusedError(f"{SECRET_VARIABLE} is not set, so nothing could be signed")
    encoded = secret.removeprefix(_SECRET_PREFIX)
    if encoded == secret:
        raise WebhookRefusedError(f"{SECRET_VARIABLE} must start with whsec_")
    try:
        key = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except binascii.Error:
        key = b""
    if not key:
        raise WebhookRefusedError(f"{SECRET_VARIABLE} must be whsec_ followed by base64")
    return key


class _RefuseRedirects(HTTPRedirectHandler):
    """Hand a redirect back as the error it is: a redirected delivery is not delivered."""

    def redirect_request(  # noqa: PLR0913, PLR0917 — the signature urllib calls
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> Request | None:
        """Decline every hop, so urllib raises the redirect as an `HTTPError`."""
        return None


def _direct_opener() -> OpenerDirector:
    """Connect straight to the destination: no proxy variable applies, and no redirect is followed.

    A proxy the environment names would see the signed summary and could answer for the
    receiver; the operator named the receiver, not the proxy.
    """
    return build_opener(ProxyHandler({}), _RefuseRedirects)


@dataclass(frozen=True, slots=True)
class _Answer:
    """What one attempt got back: a status, or no answer at all, and when to try again."""

    status: int | None
    detail: str = ""
    retry_after: str | None = None


@dataclass(slots=True)
class Webhook:
    """One prepared destination: delivers a run once, in at most three attempts."""

    destination: str
    url: str = field(repr=False)
    secret: str = field(repr=False)
    key: bytes = field(repr=False)
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    now: Callable[[], float] = time.time
    opener: OpenerDirector = field(default_factory=_direct_opener)

    def sent_secrets(self) -> tuple[str, ...]:
        """Return the signing secret and, when it says more than the destination, the URL."""
        if self.url == self.destination:
            return (self.secret,)
        return (self.secret, self.url)

    def deliver(self, verification: Verification) -> Delivery:
        """Send the run's summary and say what became of it."""
        built = build_body(verification)
        if isinstance(built, str):
            return Delivery(DeliveryStatus.NOT_SENT, detail=built)
        message_id = webhook_id(EVENT_TYPE, verification.manifest.run_id)
        deadline = self.monotonic() + DEADLINE_SECONDS
        attempts = 1
        answer = self._attempt(built, message_id, ATTEMPT_TIMEOUT_SECONDS)
        while (wait := self._retry_in(answer, attempts, deadline)) is not None:
            self.sleep(wait)
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                break
            attempts += 1
            answer = self._attempt(built, message_id, min(ATTEMPT_TIMEOUT_SECONDS, remaining))
        return _settled(answer, attempts)

    def _retry_in(self, answer: _Answer, attempts: int, deadline: float) -> float | None:
        """Return how long to wait before the next attempt, or None when this one decides."""
        if attempts >= MAX_ATTEMPTS or not _retryable(answer.status):
            return None
        if answer.retry_after is not None:
            if not _SECONDS.fullmatch(answer.retry_after.strip()):
                return None
            wait = float(answer.retry_after.strip())
        else:
            wait = BACKOFF_SECONDS[attempts - 1]
        if self.monotonic() + wait >= deadline:
            return None
        return wait

    def _attempt(self, body: bytes, message_id: str, timeout: float) -> _Answer:
        timestamp = str(int(self.now()))
        request = Request(  # noqa: S310 — the scheme was checked in prepare
            self.url,
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "webhook-id": message_id,
                "webhook-timestamp": timestamp,
                "webhook-signature": sign(self.key, message_id, timestamp, body),
            },
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                response.read(MAX_RESPONSE_BYTES)
                return _Answer(status=response.status)
        except HTTPError as exc:
            with exc:
                exc.read(MAX_RESPONSE_BYTES)
            return _Answer(status=exc.code, retry_after=exc.headers.get("Retry-After"))
        except TimeoutError:
            return _Answer(status=None, detail="timed out")
        except HTTPException:
            return _Answer(status=None, detail="the receiver's answer could not be read")
        except URLError as exc:
            return _Answer(status=None, detail=_no_answer(exc.reason))
        except OSError as exc:
            return _Answer(status=None, detail=_no_answer(exc))


def _no_answer(reason: object) -> str:
    if isinstance(reason, TimeoutError):
        return "timed out"
    if isinstance(reason, OSError) and reason.strerror:
        return reason.strerror.lower()
    return str(reason) or "no answer"


def _retryable(status: int | None) -> bool:
    return status is None or status in {_TIMEOUT, _TOO_MANY} or status >= 500  # noqa: PLR2004 — every 5xx


def _settled(answer: _Answer, attempts: int) -> Delivery:
    """Turn the deciding attempt into a delivery."""
    if answer.status is None:
        return Delivery(DeliveryStatus.UNREACHABLE, detail=answer.detail, attempts=attempts)
    if 200 <= answer.status < 300:  # noqa: PLR2004 — the success class
        return Delivery(DeliveryStatus.DELIVERED, attempts=attempts, http_status=answer.status)
    if answer.status == _GONE:
        detail = "the receiver no longer accepts deliveries"
    elif 300 <= answer.status < 400:  # noqa: PLR2004 — the redirect class
        detail = "the receiver redirected the delivery, which is not followed"
    else:
        detail = "the receiver did not accept the delivery"
    return Delivery(
        DeliveryStatus.REJECTED, detail=detail, attempts=attempts, http_status=answer.status
    )


def webhook_id(event_type: str, run_id: str) -> str:
    """Return `msg_<digest>` for one run's event: the same on every attempt and re-delivery."""
    digest = hashlib.sha256(f"{event_type}\n{run_id}".encode()).hexdigest()
    return f"msg_{digest}"


def sign(key: bytes, message_id: str, timestamp: str, body: bytes) -> str:
    """Return the `webhook-signature` value: `v1,` and HMAC-SHA256 over `id.timestamp.body`."""
    signed = message_id.encode() + b"." + timestamp.encode() + b"." + body
    digest = hmac.new(key, signed, hashlib.sha256).digest()
    return f"v1,{base64.b64encode(digest).decode('ascii')}"


def build_body(verification: Verification) -> bytes | str:
    """Return the compact JSON body, or the reason it cannot be sent."""
    manifest = verification.manifest
    moment = manifest.completed_at or manifest.started_at
    if moment is None:
        return "the run records neither when it completed nor when it started"
    result = verification.result
    ranked = sorted(result.findings, key=lambda finding: finding.severity, reverse=True)
    listed = [
        {"rule_id": f.rule_id, "severity": f.severity.name, "title": f.title}
        for f in ranked[:MAX_FINDINGS]
    ]
    data: dict[str, object] = {
        "run_id": manifest.run_id,
        "tool_version": manifest.guardana.version,
        "gate": str(verification.gate),
        "exit_code": verification.exit_code,
        "stopped_by": None if result.stopped_by is None else str(result.stopped_by),
        "open_questions": [str(question) for question in verification.open_questions],
        "counts": counts(result),
        "target": {"kind": str(manifest.target.kind), "ref": manifest.target.ref},
        "deployment": {
            item.name: getattr(manifest.deployment, item.name)
            for item in fields(manifest.deployment)
            if getattr(manifest.deployment, item.name) is not None
        },
    }
    while True:
        data["findings"] = listed
        data["findings_truncated"] = len(listed) < len(result.findings)
        envelope = {"type": EVENT_TYPE, "timestamp": moment.isoformat(), "data": data}
        body = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(body) <= MAX_BODY_BYTES:
            return body
        if not listed:
            return f"the summary is larger than {MAX_BODY_BYTES} bytes even without findings"
        listed = listed[:-1]


def counts(result: ScanResult) -> dict[str, object]:
    """Count every channel of `result`, every key present, zero included."""
    cases = dict.fromkeys(_CASE_KEYS, 0)
    for assessment in result.assessments:
        if assessment.status is AssessmentStatus.MEASURED:
            key = (
                "measured"
                if assessment.passed is None
                else ("passed" if assessment.passed else "failed")
            )
        else:
            key = str(assessment.status)
        cases[key] += 1
    suites = dict.fromkeys(_SUITE_KEYS, 0)
    for summary in result.suites.values():
        suites[str(summary.outcome)] += 1
    by_severity = {severity.name: 0 for severity in _SEVERITIES}
    for finding in result.findings:
        by_severity[finding.severity.name] += 1
    return {
        "findings": by_severity,
        "unverified": len(result.unverified),
        "waived": len(result.waived),
        "errors": len(result.errors),
        "skipped": len(result.rules_skipped),
        "shortfalls": len(result.coverage_shortfall),
        "cases": cases,
        "suites": suites,
    }
