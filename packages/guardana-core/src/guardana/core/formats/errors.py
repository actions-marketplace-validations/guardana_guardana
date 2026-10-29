class FormatError(Exception):
    """A model artifact could not be read as the format its name claims.

    Raised — never swallowed — by every reader in this package. A rule turns it
    into a visible "not scanned" finding, because an artifact nobody could parse
    is an open question, not a clean bill of health.
    """


class UnreadableFileError(FormatError):
    """The file could not be opened or read at all, so nothing about its format is known.

    Apart from a malformed file, whose bytes were read and found wrong: a rule reports
    this one as not scanned rather than as a structural verdict.
    """
