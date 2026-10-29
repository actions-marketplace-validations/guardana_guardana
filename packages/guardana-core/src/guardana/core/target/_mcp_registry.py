"""A server's entry in an MCP registry, supplied by the operator and compared with what answered.

Neither MCP revision defines registry metadata a client can observe, and `serverInfo` is
self-reported, so the entry is an input the operator gives the run — the `server.json`
the registry publishes — and never something the run fetches. What it can establish is
whether the server that answered is one the entry publishes.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

MAX_ENTRY_BYTES = 1024 * 1024
"""The largest `server.json` read; a registry entry is metadata, never a payload."""

_NAME = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")
_URL = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)"
    r"(?P<path>[^?#]*)(?:\?(?P<query>[^#]*))?(?:#.*)?$",
    re.DOTALL,
)
_VARIABLE = re.compile(r"\{[^{}]*\}")
_WEB_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": "80", "https": "443"}


class RegistryEntryError(ValueError):
    """A registry entry that cannot be read, or does not hold what a `server.json` must."""


@dataclass(frozen=True, slots=True)
class ReportedServer:
    """The name and version a server reported about itself, in `serverInfo` or discovery `_meta`."""

    name: str
    version: str

    @classmethod
    def from_info(cls, info: Mapping[str, object] | None) -> "ReportedServer | None":
        """Read a reported identity, or None when no version was reported; `""` is none."""
        if info is None:
            return None
        version = info.get("version")
        if not isinstance(version, str) or not version:
            return None
        name = info.get("name")
        return cls(name=name if isinstance(name, str) else "", version=version)


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """The parts of a registry `server.json` a run compares: name, version and remote URLs.

    Other keys are ignored. `remotes` are the published URLs, each of which may hold a
    `{variable}` standing for one or more characters other than `/`, `?` and `#`.
    """

    name: str
    version: str
    remotes: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path) -> "RegistryEntry":
        """Read a `server.json` of at most 1 MiB, raising `RegistryEntryError` for anything else."""
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_ENTRY_BYTES + 1)
        except OSError as exc:
            raise RegistryEntryError(
                f"the registry entry at {path} cannot be read: {exc.strerror or exc}"
            ) from exc
        if len(raw) > MAX_ENTRY_BYTES:
            raise RegistryEntryError(
                f"the registry entry at {path} exceeds {MAX_ENTRY_BYTES} bytes; refusing it"
            )
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RegistryEntryError(f"the registry entry at {path} is not JSON: {exc}") from exc
        return cls.from_document(document, source=f"the registry entry at {path}")

    @classmethod
    def from_document(
        cls, document: object, *, source: str = "the registry entry"
    ) -> "RegistryEntry":
        """Read a parsed `server.json`, raising `RegistryEntryError` when it is malformed."""
        if not isinstance(document, Mapping):
            raise RegistryEntryError(f"{source} is not a JSON object")
        name = document.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise RegistryEntryError(
                f"{source} has no 'name' of the form namespace/server "
                f"(letters, digits, '.', '-' and, after the '/', '_')"
            )
        version = document.get("version")
        if not isinstance(version, str) or not version:
            raise RegistryEntryError(f"{source} has no non-empty string 'version'")
        return cls(name=name, version=version, remotes=_remotes(document.get("remotes"), source))

    def publishes(self, server_url: str) -> bool:
        """Say whether `server_url` is one of the remotes this entry publishes.

        Scheme and host compare lowercased, a default port is dropped, one trailing `/`
        of the path is dropped, the query compares verbatim and a fragment is ignored.
        """
        reached = _canonical(server_url)
        if reached is None:
            return False
        return any(_matches(published, reached) for published in self.remotes)


def _remotes(raw: object, source: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise RegistryEntryError(f"{source} has a 'remotes' that is not a list")
    urls: list[str] = []
    for index, remote in enumerate(raw):
        if not isinstance(remote, Mapping) or not isinstance(remote.get("type"), str):
            raise RegistryEntryError(
                f"{source} has a remote at index {index} without a string 'type'"
            )
        url = remote.get("url")
        parts = _URL.fullmatch(url) if isinstance(url, str) else None
        if parts is None or parts["scheme"].lower() not in _WEB_SCHEMES or not parts["authority"]:
            raise RegistryEntryError(
                f"{source} has a remote at index {index} without an http or https 'url'"
            )
        urls.append(str(url))
    return tuple(urls)


def _canonical(url: str) -> tuple[str, str] | None:
    """Spell a URL the one way two equal ones share, as its address and its query.

    None when it is not a URL. The query is kept apart, so a `{variable}` in the address
    can never stand for any part of it.
    """
    parts = _URL.fullmatch(url)
    if parts is None:
        return None
    scheme = parts["scheme"].lower()
    authority = parts["authority"].rpartition("@")[2].lower()
    host, colon, port = authority.rpartition(":")
    if colon and "]" not in port and port == _DEFAULT_PORTS.get(scheme):
        authority = host
    path = parts["path"].removesuffix("/")
    return f"{scheme}://{authority}{path}", parts["query"] or ""


def _matches(published: str, reached: tuple[str, str]) -> bool:
    """Match a reached URL against a published one, its address and its query apart.

    A `{variable}` stands for `[^/?#]+` in the address and for `[^&#]+` in the query, so
    it never spans into the query or across a query parameter.
    """
    canonical = _canonical(published)
    if canonical is None:
        return False
    address, query = canonical
    return _fills(address, reached[0], "[^/?#]+") and _fills(query, reached[1], "[^&#]+")


def _fills(template: str, text: str, variable: str) -> bool:
    pattern = variable.join(re.escape(piece) for piece in _VARIABLE.split(template))
    return re.fullmatch(pattern, text, re.DOTALL) is not None


__all__ = ["MAX_ENTRY_BYTES", "RegistryEntry", "RegistryEntryError", "ReportedServer"]
