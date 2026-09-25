"""The single source of truth for parsing proxy links.

Replaces the three disagreeing implementations this project used to carry: two
``sed`` regexes inside ``nc_test.sh`` and a third ``@([^:/?]+)`` regex inside
``ping_test.py``. Everything downstream (probe, latency filter, TLS stage) reads
a link through :func:`parse_link`.

The parser is deliberately hand-rolled instead of delegating to
:func:`urllib.parse.urlsplit` because real subscription payloads are not clean
URLs: userinfo carries ``user:password`` pairs with embedded ``@`` and ``:``,
query values carry JSON with ``&`` and ``=`` inside them, fragments carry
unicode and spaces, files carry CRLF endings, and a list file is sometimes an
HTML error page. ``urlsplit`` also lowercases the host and raises on
non-numeric ports, both of which lose information we need.

Parsing never raises and never performs I/O, so it is trivially unit-testable
offline.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from dataclasses import dataclass
from typing import Iterable, Iterator, Mapping
from urllib.parse import unquote

__all__ = [
    "ParsedLink",
    "LoadStats",
    "DEFAULT_PORT",
    "parse_link",
    "iter_raw_lines",
    "dedupe",
    "load_unique",
    "load_unique_detailed",
    "filter_latency",
]

#: Port assumed when a link omits one. A missing port is never a parse failure.
DEFAULT_PORT = 443

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?$")
_MAX_PORT = 65535
# Characters that never legitimately appear in a host and strongly suggest the
# line is an error page, a log line or prose rather than a link.
_HOST_FORBIDDEN = set(" \t\r\n<>\"'{}|\\^`,")
# Trailing punctuation that survives copy/paste out of HTML lists and spreadsheets.
_TRAILING_JUNK = ",;"
# URL-safe base64 to standard base64, applied only when the standard alphabet fails.
_B64_URL_TO_STD = str.maketrans("-_", "+/")

# Schemes whose userinfo is a base64 blob wrapping `method:password@host:port`.
_BASE64_USERINFO_SCHEMES = frozenset({"ss"})

BARE_HOST_SCHEME = "tcp"


def _endpoint_key(host: str, port: int) -> str:
    """Render the ``host:port`` probe/timings cache key, bracketing IPv6 literals.

    IPv4 literals and hostnames render exactly as ``host:port``. An IPv6 literal
    is wrapped in brackets, ``[2606:4700::1]:443``, because the bare form
    ``2606:4700::1:443`` is ambiguous to read back (it is not a legal host:port
    pair) and is the join key between this module and ``netprobe``.

    ``netprobe.endpoint_str`` is a byte-identical reimplementation of this
    function; the two must never drift. The hosts reaching it come from
    :class:`ParsedLink`, which stores IPv6 without brackets.

    Args:
        host: An IP literal or DNS name, never bracketed.
        port: A TCP port in 1..65535.

    Returns:
        The cache key, e.g. ``1.2.3.4:443``, ``example.com:443`` or
        ``[2606:4700::1]:443``.
    """
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


@dataclass(frozen=True, slots=True)
class ParsedLink:
    """One parsed proxy link.

    ``uuid`` holds the percent-decoded userinfo: a UUID for vless/vmess, the
    password for trojan, the decoded ``method:password`` for ss, and ``None``
    when the link carries no userinfo. ``key`` is the dedup identity and keeps
    the *raw*, still-encoded userinfo so no two spellings of one proxy are
    conflated by accident.
    """

    raw: str
    scheme: str
    host: str
    port: int
    sni: str | None
    uuid: str | None
    key: str
    endpoint: tuple[str, int]

    @property
    def endpoint_str(self) -> str:
        """Return the probe/timings cache key, IPv6 bracketed: ``[::1]:443``.

        Byte-identical to :func:`netprobe.endpoint_str`; see :func:`_endpoint_key`.
        """
        return _endpoint_key(self.host, self.port)


@dataclass(frozen=True, slots=True)
class LoadStats:
    """Accounting for one pass over a link file, so nothing is ever lost silently."""

    total_lines: int
    parsed_lines: int
    dropped: int
    duplicates: int
    links: int
    endpoints: int


def _clean(line: str) -> str:
    """Strip whitespace, CR, surrounding quotes and trailing list punctuation."""
    text = line.strip().strip("\"'").strip()
    changed = True
    while changed:
        changed = False
        stripped = text.rstrip(_TRAILING_JUNK)
        if stripped != text:
            text = stripped
            changed = True
        text = text.rstrip()
    return text


def _valid_host(host: str) -> bool:
    """Return True when ``host`` is a plausible IP literal or DNS name."""
    if not host or len(host) > 253:
        return False
    if _HOST_FORBIDDEN & set(host):
        return False
    if host.startswith("[") or host.endswith("]"):
        return False
    if _IPV4_RE.match(host):
        return all(0 <= int(part) <= 255 for part in host.split("."))
    if ":" in host:
        return _valid_ipv6(host)
    labels = host.rstrip(".").split(".")
    if not labels or any(not _LABEL_RE.match(label) for label in labels):
        return False
    return len(labels) >= 2


def _valid_ipv6(host: str) -> bool:
    """Cheap IPv6 shape check without depending on :mod:`ipaddress` semantics."""
    if host.count("::") > 1:
        return False
    if any(not part for part in host.split(":") if part != ""):
        return False
    groups = [part for part in host.split(":") if part]
    if len(groups) > 8:
        return False
    for group in groups:
        if not group or len(group) > 4:
            return False
        try:
            int(group, 16)
        except ValueError:
            return False
    return True


def _split_port(authority: str) -> tuple[str, int | None] | None:
    """Split ``authority`` into (host, port); port is None when absent.

    Returns None when a port is present but unusable, so the caller can treat
    the line as unparseable rather than silently probing the wrong port.
    """
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return None
        host = authority[1:end]
        rest = authority[end + 1:]
        if not rest:
            return (host, None)
        if not rest.startswith(":"):
            return None
        return _finish_port(host, rest[1:])
    if authority.count(":") > 1:
        return None
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        return _finish_port(host, port)
    return (authority, None)


def _finish_port(host: str, port: str) -> tuple[str, int | None] | None:
    if not port:
        return (host, None)
    if not port.isdigit():
        return None
    value = int(port)
    if not 1 <= value <= _MAX_PORT:
        return None
    return (host, value)


def _split_params(query: str) -> list[tuple[str, str]]:
    """Split a raw query string into ordered (name, value) pairs, keeping junk.

    Values are kept exactly as written: JSON payloads legitimately contain
    ``&``, ``=``, ``#``-free braces and quotes, and re-encoding them would make
    the dedup key unstable. Empty segments are dropped.
    """
    params: list[tuple[str, str]] = []
    for chunk in query.split("&"):
        if not chunk:
            continue
        name, sep, value = chunk.partition("=")
        params.append((name, value) if sep else (name, ""))
    return params


def _sorted_query(params: Iterable[tuple[str, str]]) -> str:
    """Render params as a sorted, canonical ``a=b&c=d`` query."""
    return "&".join(f"{name}={value}" for name, value in sorted(params))


def _lookup(params: Mapping[str, str], *names: str) -> str | None:
    """Return the first non-empty value among ``names``, else None."""
    for name in names:
        value = params.get(name)
        if value:
            return value
    return None


def _build(raw: str, scheme: str, userinfo: str | None, authority: str,
           params: list[tuple[str, str]]) -> ParsedLink | None:
    """Assemble a ParsedLink from the already-split parts, or None if invalid.

    This is the single place that decides the port default, the SNI fallback and
    the dedup key, so every parse path produces identically shaped results.
    """
    split = _split_port(authority)
    if split is None:
        return None
    host, port = split
    if not _valid_host(host):
        return None
    resolved_port = DEFAULT_PORT if port is None else port

    lookup = {name: value for name, value in params}
    sni = _lookup(lookup, "sni", "host", "peer") or host
    uuid = unquote(userinfo) if userinfo else None

    identity = f"{scheme}://{userinfo}@{host}:{resolved_port}" if userinfo else f"{scheme}://{host}:{resolved_port}"
    query = _sorted_query(params)
    key = f"{identity}?{query}" if query else identity

    return ParsedLink(
        raw=raw,
        scheme=scheme,
        host=host,
        port=resolved_port,
        sni=sni,
        uuid=uuid,
        key=key,
        endpoint=(host, resolved_port),
    )


def _parse_shaped(text: str, scheme: str) -> ParsedLink | None:
    """Parse ``scheme://[userinfo@]host[:port][/path][?query][#fragment]``."""
    body = text[len(scheme) + 3:]
    cut = body.find("#")
    if cut != -1:
        body = body[:cut]
    cut = body.find("?")
    if cut != -1:
        query = body[cut + 1:]
        body = body[:cut]
        params = _split_params(query)
    else:
        params = []
    cut = -1
    for index, char in enumerate(body):
        if char == "/":
            cut = index
            break
    if cut != -1:
        body = body[:cut]

    userinfo: str | None = None
    authority = body
    if "@" in body:
        userinfo, _, authority = body.rpartition("@")
        if not userinfo:
            return None
    if not authority:
        return None
    if userinfo and scheme in _BASE64_USERINFO_SCHEMES:
        return _parse_base64_userinfo(text, scheme, userinfo, authority, params)
    return _build(text, scheme, userinfo, authority, params)


def _parse_base64_userinfo(text: str, scheme: str, userinfo: str, authority: str,
                           params: list[tuple[str, str]]) -> ParsedLink | None:
    """Decode an ``ss://`` base64 userinfo, then re-parse the inner shape.

    Two forms exist in the wild and both are handled: the blob wraps the whole
    ``method:password@host:port``, or it wraps only ``method:password`` and the
    real host sits in the outer authority.
    """
    decoded = _b64_text(userinfo)
    if decoded is None:
        return _build(text, scheme, userinfo, authority, params)
    if "@" in decoded:
        return _build(text, scheme, decoded, decoded.rpartition("@")[2], params)
    return _build(text, scheme, decoded, authority, params)


def _scheme_prefix(text: str) -> str | None:
    match = _SCHEME_RE.match(text)
    return match.group(1) if match else None


_MS_FIELD_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?\t")


def _strip_scored_prefix(text: str) -> str:
    """Drop a leading ``"<ms>\\t"`` field from a scored-artifact line.

    ``<ms>\\t<link>`` is the agreed format of the scored artifacts, so a link
    read back out of one still has to parse. Only a purely numeric first field
    followed by a tab is removed, which cannot affect a real link.
    """
    match = _MS_FIELD_RE.match(text)
    return text[match.end():] if match else text


def _b64_text(value: str) -> str | None:
    """Best-effort base64 decode to text, or None when the input is not base64.

    Accepts both the standard and URL-safe alphabets; subscription payloads
    exist in both.
    """
    padded = value.strip()
    padded += "=" * (-len(padded) % 4)
    candidates = [padded]
    translated = padded.translate(_B64_URL_TO_STD)
    if translated != padded:
        candidates.append(translated)
    for candidate in candidates:
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return None


# JSON fields that identify a vmess payload, in the order they are read. The
# resulting pairs become the sorted query of the dedup key.
_VMESS_FIELDS = ("sni", "host", "path", "type", "net", "security", "alpn", "fp", "tls")


def _parse_vmess_json(text: str, scheme: str, blob: str) -> ParsedLink | None:
    """Parse a vmess body that base64-decodes to the standard JSON config."""
    try:
        data = json.loads(blob)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    host = str(data.get("add") or "").strip()
    if not _valid_host(host):
        return None
    raw_port = data.get("port")
    if raw_port in (None, ""):
        port = DEFAULT_PORT
    else:
        try:
            port = int(str(raw_port).strip())
        except ValueError:
            return None
        if not 1 <= port <= _MAX_PORT:
            return None
    params: list[tuple[str, str]] = []
    for field in _VMESS_FIELDS:
        value = data.get(field)
        if value in (None, ""):
            continue
        params.append((field, str(value)))
    uid = str(data.get("id") or "").strip() or None
    return _build(text, scheme, uid, f"{host}:{port}", params)


def _parse_base64_body(text: str, scheme: str) -> ParsedLink | None:
    """Handle bodies that are a base64 blob rather than a ``user@host:port`` authority.

    Covers two real-world forms the plain shape grammar cannot express: a vmess
    JSON config, and an ``ss://`` link whose whole ``method:pass@host:port`` is
    encoded. Only attempted when the ordinary parse already failed, so it can
    never change the outcome of a link that parses normally.
    """
    payload = text[len(scheme) + 3:].split("#", 1)[0].split("?", 1)[0]
    decoded = _b64_text(payload)
    if decoded is None:
        return None
    if decoded.lstrip().startswith("{"):
        return _parse_vmess_json(text, scheme, decoded)
    inner_scheme = _scheme_prefix(decoded)
    if inner_scheme is not None:
        return _parse_shaped(decoded, inner_scheme)
    if "@" not in decoded:
        return None
    return _build(text, scheme, decoded.rpartition("@")[0], decoded.rpartition("@")[2], [])


def _parse_bare(text: str) -> ParsedLink | None:
    """Parse a bare ``host:port`` or ``host`` line; the port defaults to 443."""
    if "://" in text or " " in text or "\t" in text:
        return None
    if _SCHEME_RE.match(text):
        return None
    if not _HOST_FORBIDDEN & set(text):
        split = _split_port(text)
        if split is not None and _valid_host(split[0]):
            return _build(text, BARE_HOST_SCHEME, None, text, [])
    return None


def parse_link(line: str) -> ParsedLink | None:
    """Parse one link line into a :class:`ParsedLink`, or None if unparseable.

    Tolerates surrounding whitespace, CR, quotes, trailing commas, unicode and
    spaces in the fragment, and a missing port (which defaults to 443). Never
    raises.
    """
    if not isinstance(line, str):
        return None
    text = _clean(line)
    if not text:
        return None
    text = _strip_scored_prefix(text)

    match = _SCHEME_RE.match(text)
    if match is None:
        return _parse_bare(text)

    scheme = match.group(1).lower()
    if len(text) <= len(scheme) + 3:
        return None
    parsed = _parse_shaped(text, scheme)
    if parsed is not None:
        return parsed
    return _parse_base64_body(text, scheme)


def iter_raw_lines(path: str | os.PathLike[str]) -> Iterator[str]:
    """Yield non-blank lines from ``path`` with only the line terminator removed.

    Decoding is lenient (``errors="replace"``) so a stray byte never aborts a
    run, and I/O errors are allowed to propagate so the caller can report them.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.rstrip("\r\n")
            if text.strip():
                yield text


def dedupe(lines: Iterable[str]) -> tuple[list[str], int]:
    """Collapse duplicates, returning ``(unique_lines_in_first_seen_order, duplicate_count)``.

    Identity is the :func:`parse_link` key, so one proxy carrying two different
    ``#note`` fragments collapses to a single entry. Lines that fail to parse
    fall back to their stripped text, so unparseable junk collapses instead of
    multiplying.
    """
    seen: set[str] = set()
    unique: list[str] = []
    duplicates = 0
    for line in lines:
        if not isinstance(line, str):
            continue
        text = _clean(line)
        if not text:
            continue
        parsed = parse_link(text)
        identity = parsed.key if parsed is not None else text
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        unique.append(text)
    return unique, duplicates


def _analyse(lines: Iterable[str]) -> tuple[list[ParsedLink], LoadStats]:
    """Shared core of :func:`load_unique` and :func:`load_unique_detailed`."""
    total = 0
    parsed_lines = 0
    seen: set[str] = set()
    links: list[ParsedLink] = []
    duplicates = 0

    for line in lines:
        text = _clean(line) if isinstance(line, str) else ""
        if not text:
            continue
        total += 1
        parsed = parse_link(text)
        if parsed is None:
            continue
        parsed_lines += 1
        if parsed.key in seen:
            duplicates += 1
            continue
        seen.add(parsed.key)
        links.append(parsed)

    stats = LoadStats(
        total_lines=total,
        parsed_lines=parsed_lines,
        dropped=total - parsed_lines,
        duplicates=duplicates,
        links=len(links),
        endpoints=len({link.endpoint for link in links}),
    )
    return links, stats


def load_unique(path: str | os.PathLike[str]) -> tuple[list[ParsedLink], int]:
    """Parse, dedupe and drop unparseable lines from ``path``.

    Returns ``(links, dropped_count)`` where ``dropped_count`` counts input
    lines that could not be parsed at all. Duplicates are collapsed rather than
    counted as dropped; use :func:`load_unique_detailed` when the full
    accounting is needed for the final report.
    """
    links, stats = _analyse(iter_raw_lines(path))
    return links, stats.dropped


def load_unique_detailed(path: str | os.PathLike[str]) -> tuple[list[ParsedLink], LoadStats]:
    """Like :func:`load_unique` but returns the full :class:`LoadStats` accounting.

    The dropped and duplicate counts are what make spec requirement 3 (no
    silent loss) reportable, so the final report should call this.
    """
    return _analyse(iter_raw_lines(path))


def filter_latency(
    links: Iterable[ParsedLink],
    timings: Mapping[str, float | None],
    max_ms: float,
) -> tuple[list[ParsedLink], list[ParsedLink]]:
    """Split links into ``(within_threshold, rejected)`` on the timings mapping.

    An endpoint that is missing from ``timings`` or mapped to None failed the
    probe stage and is therefore rejected, never passed through. ``within`` is
    sorted by ascending milliseconds with a stable sort; ``rejected`` keeps its
    input order.
    """
    within: list[tuple[float, ParsedLink]] = []
    rejected: list[ParsedLink] = []
    for link in links:
        measured = timings.get(link.endpoint_str)
        if measured is None:
            rejected.append(link)
            continue
        try:
            ms = float(measured)
        except (TypeError, ValueError):
            rejected.append(link)
            continue
        if ms > max_ms:
            rejected.append(link)
            continue
        within.append((ms, link))
    within.sort(key=lambda pair: pair[0])
    return [link for _, link in within], rejected
