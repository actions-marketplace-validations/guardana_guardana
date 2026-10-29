"""Text a target wrote, made safe to print in a terminal."""


def printable(line: str) -> str:
    """Escape every control character in one report line, newlines included.

    Evidence, titles and references are text the target wrote: an escape sequence in
    them can clear or repaint the warning above it, a bidirectional override can make
    the line read in an order it was not written in, and a newline can forge a line of
    the report. The only line breaks printed are the ones `render` joins with.
    """
    if line.isprintable():
        return line
    return "".join(_CONTROL_ESCAPES.get(c, c) for c in line)


_BIDI_AND_LINE_CONTROLS = (
    0x061C,
    0x200E,
    0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
    0x2028,
    0x2029,
)

_CONTROL_ESCAPES = {
    chr(code): chr(code).encode("unicode_escape").decode("ascii")
    for code in (*range(0x20), *range(0x7F, 0xA0), *_BIDI_AND_LINE_CONTROLS)
}
