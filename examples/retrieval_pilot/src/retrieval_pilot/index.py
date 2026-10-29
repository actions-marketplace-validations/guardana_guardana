"""A keyword index over the `documents.jsonl` that `guardana fixtures render` writes."""

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

_WORD = re.compile(r"[^\W_]+")


def words(text: str) -> frozenset[str]:
    """Return the case-folded words of `text`."""
    return frozenset(match.group(0).casefold() for match in _WORD.finditer(text))


@dataclass(frozen=True, slots=True)
class Document:
    """One indexed document and the tenant that owns it."""

    id: str
    tenant: str
    text: str


class KeywordIndex:
    """Ranks documents by the words they share with a question.

    A word every document holds ranks nothing, so a question that shares only those
    finds no document rather than an arbitrary one.
    """

    def __init__(self, documents: Sequence[Document]) -> None:
        """Index `documents`; the earlier of two equal matches wins."""
        self._documents = tuple(documents)
        self._words = [words(document.text) for document in self._documents]
        self._common = frozenset.intersection(*self._words) if self._words else frozenset()

    @classmethod
    def load(cls, path: Path) -> "KeywordIndex":
        """Read one JSON object per line with string `id`, `tenant` and `text`, or raise."""
        documents: list[Document] = []
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            fields = [entry.get(key) if isinstance(entry, dict) else None for key in _FIELDS]
            if not all(isinstance(value, str) for value in fields):
                raise ValueError(f"{path}:{number}: expected string id, tenant and text")
            documents.append(Document(*(str(value) for value in fields)))
        return cls(documents)

    @property
    def documents(self) -> tuple[Document, ...]:
        """Every indexed document, in the order it was loaded."""
        return self._documents

    def search(self, question: str, tenant: str, *, filtered: bool = True) -> Document | None:
        """Return the best match `tenant` may read, or None when nothing matches.

        `filtered=False` searches every tenant's documents: the broken filter.
        """
        asked = words(question) - self._common
        best: tuple[int, Document] | None = None
        for document, held in zip(self._documents, self._words, strict=True):
            if filtered and document.tenant != tenant:
                continue
            score = len(asked & held)
            if score and (best is None or score > best[0]):
                best = (score, document)
        return None if best is None else best[1]


_FIELDS = ("id", "tenant", "text")

__all__ = ["Document", "KeywordIndex", "words"]
