import builtins
import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

_ALGORITHM = "sha256"
_SEPARATOR = b"\x00"


def digest_of(*parts: str) -> str:
    """Hash `parts` into an algorithm-qualified digest, e.g. `sha256:1a2b…`.

    Two decisions, both about what a digest has to survive.

    **The algorithm is named, never implied.** A bare hex string cannot be
    migrated when the algorithm moves, because nothing in the document says what
    produced it — and an evidence record outlives the release that wrote it.

    **Parts are separated by a byte that cannot occur in them.** Concatenating
    naively makes `("ab", "c")` and `("a", "bc")` hash identically, so two
    different targets would claim one fingerprint and a comparison would treat
    them as the same deployment.
    """
    digest = hashlib.sha256(_SEPARATOR.join(part.encode("utf-8") for part in parts))
    return f"{_ALGORITHM}:{digest.hexdigest()}"


_DOCUMENT_DIGEST = re.compile(rf"{_ALGORITHM}:[0-9a-f]{{64}}")


class DigestKind(StrEnum):
    """What a document digest covers, so a reader never takes a prefix for the whole."""

    CONTENT = "content"
    """Every byte of the document: the reader saw it end."""

    CONTENT_PREFIX = "content_prefix"
    """The bytes read before a read ceiling stopped the reader, and nothing after them."""


@dataclass(frozen=True, slots=True)
class DocumentDigest:
    """The digest of the first `bytes` bytes of a document, and whether that was all of it.

    `digest` is the SHA-256 of exactly those bytes, so anyone holding the file can check
    it with `head -c <bytes> <file> | sha256sum`.
    """

    digest: str
    kind: DigestKind
    bytes: int

    def __post_init__(self) -> None:
        """Refuse a digest no reader of a document could have produced."""
        if not isinstance(self.kind, DigestKind):
            raise TypeError(f"a document digest's kind is a DigestKind, not {self.kind!r}")
        if isinstance(self.bytes, bool) or not isinstance(self.bytes, int):
            raise TypeError(f"a document digest covers a whole number of bytes, not {self.bytes!r}")
        if self.bytes < 0:
            raise ValueError(f"a document digest covers a byte count >= 0, not {self.bytes}")
        if not isinstance(self.digest, str) or not _DOCUMENT_DIGEST.fullmatch(self.digest):
            raise ValueError(
                f"a document digest is '{_ALGORITHM}:' and 64 lowercase hex digits, "
                f"not {self.digest!r}"
            )

    @classmethod
    def of(cls, data: builtins.bytes, kind: DigestKind) -> "DocumentDigest":
        """Digest `data`, which is every byte read from the start of the document."""
        return cls(f"{_ALGORITHM}:{hashlib.sha256(data).hexdigest()}", kind, len(data))
