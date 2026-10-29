#!/usr/bin/env python3
"""Generate the files browsers and scanners ask guardana.dev for without a page linking them.

    uv run python scripts/generate_well_known.py            # write them
    uv run python scripts/generate_well_known.py --check    # exit 1 if stale; write nothing

- `site/favicon.ico` (16, 32 and 48 px) and `site/apple-touch-icon.png` with its
  `-precomposed` twin (180 px), rendered from `site/favicon.svg`. The Apple icon is
  drawn with square corners, because iOS applies its own mask and paints transparent
  pixels black.
- `site/.well-known/security.txt` (RFC 9116), whose contacts are read from the
  "Reporting a vulnerability" section of `SECURITY.md` so the two cannot disagree.

Icons are compared by their pixels, not their bytes: two zlib builds may compress the
same image differently, and a file whose pixels already match is left alone.

`Expires` is kept while it is at least 90 days away and refreshed to 180 days from
today otherwise, so a release keeps it current; `--check` fails once it is under 30
days away or more than a year ahead, the limit RFC 9116 recommends.
"""

import argparse
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_SITE = _REPO / "site"
_SECURITY_MD = _REPO / "SECURITY.md"
_ORIGIN = "https://guardana.dev"
_POLICY = "https://github.com/guardana/guardana/blob/main/SECURITY.md"

sys.path.insert(0, str(_REPO / "scripts"))

from sitegen import icon  # noqa: E402
from sitegen.errors import SiteBuildError  # noqa: E402

_FAVICON_SIZES = (16, 32, 48)
_TOUCH_SIZE = 180
_TOUCH_ICONS = ("apple-touch-icon.png", "apple-touch-icon-precomposed.png")
_SECURITY_TXT = ".well-known/security.txt"

_LIFETIME = timedelta(days=180)
_REFRESH_WITHIN = timedelta(days=90)
_STALE_WITHIN = timedelta(days=30)
_MAX_AHEAD = timedelta(days=365)

_REPORTING = re.compile(
    r"^## Reporting a vulnerability\n(?P<body>.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL
)
_ADVISORY = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/security/advisories/new")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_EXPIRES = re.compile(r"^Expires: (\S+)$", re.MULTILINE)


def contacts(security_md: str) -> list[str]:
    """Return the private reporting channels SECURITY.md names, in its order of preference."""
    section = _REPORTING.search(security_md)
    if section is None:
        raise SiteBuildError("SECURITY.md has no '## Reporting a vulnerability' section")
    body = section.group("body")
    found = [*dict.fromkeys(_ADVISORY.findall(body))]
    found += [f"mailto:{email}" for email in dict.fromkeys(_EMAIL.findall(body))]
    if not found:
        raise SiteBuildError("SECURITY.md names no advisory URL or email to report to")
    return found


def security_txt(security_md: str, expires: datetime) -> str:
    """Build the RFC 9116 file for this site, expiring at `expires`."""
    lines = [f"Contact: {contact}" for contact in contacts(security_md)]
    lines += [
        f"Expires: {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "Preferred-Languages: en",
        f"Policy: {_POLICY}",
        f"Canonical: {_ORIGIN}/{_SECURITY_TXT}",
    ]
    return "\n".join(lines) + "\n"


def _expires_in(text: str) -> datetime | None:
    match = _EXPIRES.search(text)
    if match is None:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _next_expires(existing: datetime | None, now: datetime) -> datetime:
    if existing is not None and now + _REFRESH_WITHIN <= existing <= now + _MAX_AHEAD:
        return existing
    day = (now + _LIFETIME).date()
    return datetime(day.year, day.month, day.day, tzinfo=UTC)


def _icons(svg: str) -> dict[str, dict[int, bytes]]:
    """Map each published icon to the pixels every size of it must hold."""
    touch = {_TOUCH_SIZE: icon.render(svg, _TOUCH_SIZE, full_bleed=True)}
    wanted = {"favicon.ico": {size: icon.render(svg, size) for size in _FAVICON_SIZES}}
    wanted.update(dict.fromkeys(_TOUCH_ICONS, touch))
    return wanted


def _pixels(path: Path) -> dict[int, bytes] | None:
    if not path.is_file():
        return None
    data = path.read_bytes()
    if path.suffix == ".ico":
        return icon.ico_pixels(data)
    decoded = icon.png_pixels(data)
    return None if decoded is None else {decoded[0]: decoded[1]}


def stale(site: Path, security_md: Path, now: datetime) -> list[str]:
    """List the generated files under `site` that are missing, out of date, or expiring soon."""
    source = security_md.read_text(encoding="utf-8")
    out = [
        name
        for name, wanted in _icons((site / "favicon.svg").read_text(encoding="utf-8")).items()
        if _pixels(site / name) != wanted
    ]
    target = site / _SECURITY_TXT
    text = target.read_text(encoding="utf-8") if target.is_file() else ""
    expires = _expires_in(text)
    if (
        expires is None
        or not now + _STALE_WITHIN <= expires <= now + _MAX_AHEAD
        or text != security_txt(source, expires)
    ):
        out.append(_SECURITY_TXT)
    return out


def write(site: Path, security_md: Path, now: datetime) -> list[str]:
    """Rewrite what `stale` would report, and nothing else; returns what was written."""
    source = security_md.read_text(encoding="utf-8")
    written = []
    for name, wanted in _icons((site / "favicon.svg").read_text(encoding="utf-8")).items():
        path = site / name
        if _pixels(path) == wanted:
            continue
        if path.suffix == ".ico":
            path.write_bytes(icon.ico(wanted))
        else:
            ((size, rgba),) = wanted.items()
            path.write_bytes(icon.png(rgba, size))
        written.append(name)
    target = site / _SECURITY_TXT
    existing = target.read_text(encoding="utf-8") if target.is_file() else ""
    text = security_txt(source, _next_expires(_expires_in(existing), now))
    if text != existing:
        target.parent.mkdir(exist_ok=True)
        target.write_text(text, encoding="utf-8")
        written.append(_SECURITY_TXT)
    return written


def main() -> int:
    """Write the files, or report which of them no longer match their sources."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if a file is out of date; write nothing"
    )
    arguments = parser.parse_args()
    now = datetime.now(UTC)

    try:
        return _check(now) if arguments.check else _write(now)
    except SiteBuildError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _check(now: datetime) -> int:
    out_of_date = stale(_SITE, _SECURITY_MD, now)
    if out_of_date:
        print(f"site/{', site/'.join(out_of_date)} is out of date", file=sys.stderr)
        print("run `uv run python scripts/generate_well_known.py`", file=sys.stderr)
        return 1
    print("site/favicon.ico, the Apple touch icons and site/.well-known/security.txt are current")
    return 0


def _write(now: datetime) -> int:
    written = write(_SITE, _SECURITY_MD, now)
    print(
        f"wrote {', '.join(f'site/{name}' for name in written)}" if written else "nothing to write"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
