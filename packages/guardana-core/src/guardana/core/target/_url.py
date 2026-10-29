"""How a target URL is shown and saved: without the parts a credential hides in.

Userinfo, a query and a fragment can each carry a key. A `ref` lands in the run
document, SARIF, the collector and every error message, so it is built from this
function and never from the raw address. The raw address is still what a transport
sends to.
"""

import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from guardana.core.fingerprint import digest_of

_SHOWN_SCHEMES = frozenset({"http", "https"})
_QUERY_PLACEHOLDER = "[redacted:query:{digest}]"
_ALREADY_SHOWN = re.compile(r"\[redacted:query:[0-9a-f]{12}\]")
_UNREADABLE = "[redacted:url:{digest}]"


def private_url_parts(url: str) -> tuple[str, ...]:
    """Name the parts of `url` that can carry a credential: userinfo, query, fragment.

    Empty for a URL that has none of them. A URL that does not parse is reported as
    carrying all three, because nothing about it can be shown safely, and so is one
    whose password ended the host early at a `/`, `?` or `#`.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return ("userinfo", "query", "fragment")
    if _password_cut_the_host_short(parts):
        return ("userinfo", "query", "fragment")
    present = (
        ("userinfo", "@" in parts.netloc),
        ("query", bool(parts.query)),
        ("fragment", bool(parts.fragment)),
    )
    return tuple(name for name, found in present if found)


def display_url(url: str) -> str:
    """Return `url` as it may be shown or saved.

    An http(s) URL without userinfo, a query or a fragment comes back byte for byte,
    because a `ref` is part of a finding's identity and a respelled one would read as
    a different target. Otherwise userinfo and the fragment are dropped and the query
    becomes `[redacted:query:<digest>]`: the digest keeps two deployments that differ
    only by a query apart, and the shape is one the evidence redactor leaves alone.
    Any other scheme is returned unchanged. When a password split by `/`, `?` or `#`
    leaves no telling where the host begins, the whole URL becomes
    `[redacted:url:<digest>]`.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return _UNREADABLE.format(digest=_short_digest(url))
    if _password_cut_the_host_short(parts):
        return _UNREADABLE.format(digest=_short_digest(url))
    if parts.scheme not in _SHOWN_SCHEMES or not private_url_parts(url):
        return url
    netloc = parts.netloc.rpartition("@")[2]
    query = parts.query
    if query and not _ALREADY_SHOWN.fullmatch(query):
        query = _QUERY_PLACEHOLDER.format(digest=_short_digest(query))
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def _password_cut_the_host_short(parts: SplitResult) -> bool:
    """Whether a password holding `/`, `?` or `#` ended the host early.

    Its tell is a port that is not a number, an `@` inside a path segment (never at
    its start, as in `/@scope`), or an `@` in the query or fragment of a URL whose
    path is empty because the host ended at the `?` or `#`.
    """
    try:
        _ = parts.port
    except ValueError:
        if not parts.netloc.rpartition("@")[2].rpartition(":")[2].isdigit():
            return True
    if any("@" in segment[1:] for segment in parts.path.split("/")):
        return True
    return not parts.path and any("@" in part for part in (parts.query, parts.fragment))


def _short_digest(value: str) -> str:
    return digest_of(value).split(":", 1)[1][:12]
