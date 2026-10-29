"""Package names and versions read the way pip compares them, without `packaging`.

Covers what matching a pin against an advisory needs: PEP 503 name normalisation,
and PEP 440 versions with the optional `v` prefix, the epoch, the release segment
(numeric, trailing zeros ignored), pre-, post- and dev-release markers in every
spelling PEP 440 normalises, and a local label. Specifier sets, prefix matching
(`==1.2.*`), compatible release (`~=`) and legacy non-PEP 440 versions are out of
scope: a version this cannot read parses as None and is never guessed at.
"""

import re
from dataclasses import dataclass, replace

_PEP440 = re.compile(
    r"""
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:-(?P<post_implicit>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>[0-9]+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    """,
    re.VERBOSE,
)
_PRE_SPELLINGS = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}
_PRE_RANK = {"a": 0, "b": 1, "rc": 2}
_NAME_SEPARATORS = re.compile(r"[-_.]+")


def canonical_name(name: str) -> str:
    """Return the PEP 503 normalised form of a package name."""
    return _NAME_SEPARATORS.sub("-", name).lower()


@dataclass(frozen=True)
class Version:
    """One PEP 440 version in normalised form; equality is PEP 440 version equality."""

    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None
    local: tuple[int | str, ...] | None

    @property
    def public(self) -> "Version":
        """The same version without its local label."""
        return replace(self, local=None)

    @property
    def base(self) -> tuple[int, tuple[int, ...]]:
        """The epoch and release segment, which order a version before any marker."""
        return (self.epoch, self.release)

    def sort_key(self) -> tuple[int, tuple[int, ...], tuple[int, int], int, tuple[int, int]]:
        """Order public versions as PEP 440 does: dev < pre < final < post."""
        if self.pre is not None:
            pre = (_PRE_RANK[self.pre[0]], self.pre[1])
        elif self.post is None and self.dev is not None:
            pre = (-1, 0)
        else:
            pre = (3, 0)
        post = -1 if self.post is None else self.post
        dev = (1, 0) if self.dev is None else (0, self.dev)
        return (self.epoch, self.release, pre, post, dev)


def parse_version(text: str) -> Version | None:
    """Parse a PEP 440 version in any spelling it normalises; None when it is not one."""
    match = _PEP440.fullmatch(text.strip().lower())
    if match is None:
        return None
    release = tuple(int(part) for part in match["release"].split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    pre = None
    if match["pre_l"] is not None:
        letter = _PRE_SPELLINGS.get(match["pre_l"], match["pre_l"])
        pre = (letter, int(match["pre_n"] or 0))
    post = None
    if match["post_implicit"] is not None:
        post = int(match["post_implicit"])
    elif match["post_l"] is not None:
        post = int(match["post_n"] or 0)
    dev = None if match["dev_l"] is None else int(match["dev_n"] or 0)
    local = None
    if match["local"] is not None:
        local = tuple(
            int(part) if part.isdigit() else part for part in _NAME_SEPARATORS.split(match["local"])
        )
    return Version(int(match["epoch"] or 0), release, pre, post, dev, local)
