"""TLS handshake probing stage.

Reads ``<ms>\\t<link>`` (or bare ``<link>``) lines, performs one TLS handshake per
distinct ``(host, port, sni, insecure)`` endpoint, and splits the result into a
sorted success artifact plus a complete failure artifact.

Nothing is ever dropped: every non-blank input line lands in exactly one of
``output_file`` or ``faulty_file``. Unparseable lines are recorded as failures
rather than silently discarded.

Error slugs
-----------
Every failure this module reports carries a lowercase slug from
:data:`ERROR_SLUGS`, which is the documented vocabulary. ``timeout``,
``refused``, ``dns``, ``unreachable``, ``tls`` and ``other`` are the base set
the refactor spec defines. ``cert`` and ``parse`` are documented extensions of
that base set and are deliberately NOT folded into it, because both are facts
the reader needs that the base vocabulary would destroy:

``cert``
    The peer presented a certificate that did not verify. That is a distinct,
    actionable outcome (expired, self-signed, wrong name) and collapsing it into
    ``tls`` would tell the operator to go look at the TLS stack when the answer
    is "that certificate is bad".

``parse``
    The line is not a link at all -- an HTML error page, a log line, a bare
    ``host:notaport``. It is not a network fault, so reporting it as ``dns`` or
    ``other`` would blame the network for a bad input file.
"""

from __future__ import annotations

import errno
import math
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterator, Sequence
from urllib.parse import parse_qsl, urlsplit

import Config
import links
import progress

TAB = "\t"
CHUNK_SIZE = 256

_INSECURE_KEYS = ("allowinsecure", "insecure", "skip-cert-verify", "allow_insecure")
#: Accepted legacy spelling of the millisecond field. The primary format is a
#: BARE number, which is what :func:`_render` writes; see the module docstring
#: of :func:`_as_ms`.
_MS_SUFFIX = "_ms"
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_UNREACHABLE = frozenset({errno.EHOSTUNREACH, errno.ENETUNREACH})
_REFUSED = frozenset({errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED})
_TIMED_OUT = frozenset({errno.ETIMEDOUT})

#: Every slug this module can emit, base vocabulary plus the two documented
#: extensions. See the module docstring. Consumers that validate a failure row
#: should test membership here rather than hard-coding a list.
_SLUGS = ("cert", "dns", "other", "parse", "refused", "timeout", "tls", "unreachable")
ERROR_SLUGS = frozenset(_SLUGS)

#: A scored field: a bare non-negative decimal, optionally carrying the legacy
#: ``_ms`` suffix. Deliberately digits-only, so a negative value, ``nan``, an
#: infinity and any prose are all rejected by construction -- see :func:`_as_ms`.
_SCORE_FIELD_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?(?:_ms)?$", re.IGNORECASE)

#: A known reason slug, which this module's own failure artifact writes as the
#: leading field. Stripping it recovers the link when a failure artifact is fed
#: back in as input; it is never a millisecond value.
_SLUG_FIELD_RE = re.compile(r"^(?:%s)$" % "|".join(_SLUGS), re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class _Entry:
    """One non-blank input line resolved into the work it implies."""

    link_text: str
    link: links.ParsedLink | None
    planned_ms: float | None


def tls_check(
    host: str,
    port: int,
    sni: str | None,
    timeout: float,
    *,
    insecure: bool = False,
) -> tuple[bool, float | None, str | None]:
    """Perform one TLS handshake and time the handshake only.

    ``timeout`` is a value in SECONDS. The TCP connect is issued untimed because
    the probe stage has already measured connectivity; ``perf_counter`` is started
    immediately before ``wrap_socket`` so the reported number is handshake time.

    Returns ``(ok, handshake_ms, error_slug)`` -- always a 3-tuple. The previous
    implementation returned a bare ``False`` on failure, which its caller then
    indexed as ``tls_test[1]``; that ``TypeError`` is the bug this module removes.
    """
    if not host:
        return False, None, "dns"

    try:
        context = ssl.create_default_context()
    except OSError as exc:
        return False, None, _oserror_slug(exc)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    raw_sock: socket.socket | None = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
    except TimeoutError:
        return False, None, "timeout"
    except socket.gaierror:
        return False, None, "dns"
    except OSError as exc:
        return False, None, _oserror_slug(exc)

    try:
        raw_sock.settimeout(timeout)
        started = time.perf_counter()
        with context.wrap_socket(raw_sock, server_hostname=sni or host) as tls_sock:
            handshake_ms = (time.perf_counter() - started) * 1000.0
            tls_sock.getpeercert()
    except TimeoutError:
        return False, None, "timeout"
    except ssl.SSLCertVerificationError:
        return False, None, "cert"
    except ssl.SSLError as exc:
        return False, None, _ssl_slug(exc)
    except OSError as exc:
        return False, None, _oserror_slug(exc)

    return True, round(handshake_ms, 2), None


def _oserror_slug(exc: BaseException) -> str:
    """Classify a socket-layer OSError into a lowercase error slug."""
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "dns"
    code = getattr(exc, "errno", None)
    if code is None:
        return "other"
    if code in _UNREACHABLE:
        return "unreachable"
    if code in _REFUSED:
        return "refused"
    if code in _TIMED_OUT:
        return "timeout"
    if code == errno.ENOENT:
        return "dns"
    return "other"


def _ssl_slug(exc: BaseException) -> str:
    """Classify an SSL-layer failure into a lowercase error slug."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "cert"
    if isinstance(exc, ssl.SSLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, str) and "HANDSHAKE_FAILURE" in reason.upper():
            return "tls"
    return "other"


def _resolve_timeout(timeout: float | None) -> float:
    """Resolve the effective handshake timeout, or read it from Config.

    ``None`` means "whatever :mod:`Config` currently says". Resolving at CALL
    time rather than binding it as an argument default is what makes the CLI's
    ``--set TLS_TIMEOUT=...`` reach this stage; a default argument is evaluated
    once, at function-definition time, and would silently ignore every later
    :func:`Config.apply_overrides`. This mirrors ``netprobe._resolve_timeout``
    exactly, including the hard-coded fallback for a missing Config.
    """
    if timeout is not None:
        return float(timeout)
    return float(getattr(Config, "TLS_TIMEOUT", 3.0))


def _resolve_workers(max_workers: int | None) -> int:
    """Resolve the effective worker count, or read it from Config.

    Same call-time rationale as :func:`_resolve_timeout`; same shape as
    ``netprobe._resolve_workers``, including the floor of 1 worker.
    """
    if max_workers is not None:
        return max(1, int(max_workers))
    return max(1, int(getattr(Config, "TLS_THREADS", 30)))


def tls_runner_threaded(
    input_file: str,
    output_file: str,
    faulty_file: str | None = None,
    *,
    timeout: float | None = None,
    max_workers: int | None = None,
) -> dict[str, int]:
    """Handshake-test every link in ``input_file`` and write both outcome artifacts.

    ``input_file`` lines are ``<ms>\\t<link>`` but a bare ``<link>`` is also
    tolerated, since the file may have been produced by another stage or
    hand-edited. The link text is echoed back byte-for-byte.

    ``output_file`` receives ``<ms>\\t<link>`` for successes, ascending by ms.
    ``faulty_file`` receives ``<ms>\\t<link>`` when a timing is known and
    ``<reason>\\t<link>`` otherwise -- for every failure. ``reason`` is a slug
    from :data:`ERROR_SLUGS`.

    ``timeout``/``max_workers`` default to ``None``, meaning "read the current
    value out of :mod:`Config`". They are resolved at call time rather than bound
    as argument defaults so that ``Config.apply_overrides()`` from the CLI takes
    effect; see :func:`_resolve_timeout`.

    Returns ``{"tested", "ok", "failed"}``.
    """
    entries, skipped = _read_entries(input_file)
    timeout = _resolve_timeout(timeout)
    max_workers = _resolve_workers(max_workers)

    with progress.stage("TLS handshake", len(entries)) as st:
        cache: dict[tuple[str, int, str | None, bool], tuple[bool, float | None, str | None]] = {}
        out_rows: list[tuple[float, str]] = []
        faulty_rows: list[tuple[float | None, str, str]] = []

        for batch in _batched(entries, CHUNK_SIZE):
            for entry, outcome in _handshake_batch(batch, cache, timeout, max_workers, st):
                _record(entry, outcome, out_rows, faulty_rows)

        out_rows.sort(key=lambda row: (row[0], row[1]))
        with open(output_file, "w", encoding="utf-8") as handle:
            for ms, link_text in out_rows:
                handle.write(f"{_render(ms)}{TAB}{link_text}\n")

        faulty_rows.sort(key=lambda row: (row[0] is None, row[0] or 0.0, row[1], row[2]))
        if faulty_file is not None:
            with open(faulty_file, "w", encoding="utf-8") as handle:
                for ms, reason, link_text in faulty_rows:
                    field = reason if ms is None else _render(ms)
                    handle.write(f"{field}{TAB}{link_text}\n")

        st.log(
            f"{progress.paint('tls:', 'bold')} {progress.paint(str(len(out_rows)), 'green')} ok / "
            f"{progress.paint(str(len(faulty_rows)), 'red')} failed "
            f"over {len(cache)} distinct endpoint(s), {skipped} blank line(s) skipped"
        )

    return {"tested": len(entries), "ok": len(out_rows), "failed": len(faulty_rows)}


def _read_entries(input_file: str) -> tuple[list[_Entry], int]:
    """Parse the input file into work items, preserving original link text."""
    entries: list[_Entry] = []
    skipped = 0
    with open(input_file, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                skipped += 1
                continue
            leading, link_text = _split_line(line)
            entries.append(
                _Entry(
                    link_text=link_text,
                    link=links.parse_link(link_text),
                    planned_ms=leading,
                )
            )
    return entries, skipped


def _split_line(line: str) -> tuple[float | None, str]:
    """Split a ``<field>\\t<link>`` line, tolerating a bare link.

    A tab is only a FIELD SEPARATOR when the text before it is a leading score
    (:data:`_SCORE_FIELD_RE`) or a known reason slug (:data:`_SLUG_FIELD_RE`).
    Anything else keeps the line whole, because then the leading text is part of
    the link: ``vless://u@h:9002?a=1#tab<TAB>here`` is a bare link whose fragment
    happens to contain a tab, and splitting it would destroy the link and file
    the fragment tail as a ``parse`` failure. Splitting on the first tab
    unconditionally loses real links, and the pipeline feeds this stage BARE
    links, so that is the happy path, not an edge case.

    This is the same rule :func:`links._strip_scored_prefix` applies, kept local
    because this module must additionally recognise the reason-slug field its own
    failure artifact writes. It is a numeric regex, never a "non-empty first
    field" test, so a link whose first field merely looks numeric is not mangled
    either: a real link never begins with bare digits followed by a tab.

    Returns ``(planned_ms, link_text)``. ``planned_ms`` is ``None`` when the
    line was bare or carried a slug rather than a timing, and the link text is
    always preserved byte-for-byte.
    """
    head, tab, rest = line.partition(TAB)
    if not tab or not rest.strip():
        return None, line
    if _SCORE_FIELD_RE.match(head.strip()):
        return _as_ms(head), rest
    if _SLUG_FIELD_RE.match(head.strip()):
        return None, rest
    return None, line


def _as_ms(field: str) -> float | None:
    """Interpret a leading artifact field as a millisecond timing, or ``None``.

    The project's agreed scored-artifact format is a BARE number, ``<ms>\\t<link>``,
    which is exactly what :func:`_render` emits -- so a bare non-negative decimal
    is the PRIMARY accepted spelling. The ``_ms`` suffix is retained as an
    accepted legacy spelling because artifacts carrying it exist in the wild and
    rejecting it would drop a real measurement; :func:`_render` never writes it,
    so it can never be produced from here.

    Anything else is rejected and returns ``None``: a negative value, ``nan``,
    an infinity, an empty field, arbitrary text, or a reason slug. Rejection is
    clean and total -- it never raises -- and the caller (:func:`_split_line`)
    only ever reaches here for a field already matched by
    :data:`_SCORE_FIELD_RE`, so a rejected score costs a timing, never a link.
    """
    candidate = field.strip()
    if not _SCORE_FIELD_RE.match(candidate):
        return None
    if candidate.lower().endswith(_MS_SUFFIX):
        candidate = candidate[: -len(_MS_SUFFIX)]
    try:
        value = float(candidate)
    except ValueError:  # pragma: no cover - unreachable past _SCORE_FIELD_RE
        return None
    # Unreachable for the same reason, but kept: this is the one place that
    # decides a number is a usable timing, so it must be true independently of
    # the regex above.
    if not math.isfinite(value) or value < 0.0:
        return None
    return value


def _batched(entries: Sequence[_Entry], size: int) -> Iterator[Sequence[_Entry]]:
    """Yield slices of at most ``size`` entries so in-flight futures stay bounded."""
    step = max(1, size)
    for start in range(0, len(entries), step):
        yield entries[start : start + step]


def _handshake_batch(
    batch: Sequence[_Entry],
    cache: dict[tuple[str, int, str | None, bool], tuple[bool, float | None, str | None]],
    timeout: float,
    max_workers: int,
    st: progress.Stage,
) -> list[tuple[_Entry, tuple[bool, float | None, str | None]]]:
    """Run one bounded batch of handshakes, populating the endpoint cache."""
    todo: list[tuple[str, int, str | None, bool]] = []
    seen: set[tuple[str, int, str | None, bool]] = set()
    for entry in batch:
        key = _cache_key(entry)
        if key is None or key in cache or key in seen:
            continue
        seen.add(key)
        todo.append(key)

    if todo:
        workers = max(1, min(max_workers, len(todo)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(tls_check, host, port, sni, timeout, insecure=insecure)
                for host, port, sni, insecure in todo
            ]
            for key, future in zip(todo, futures):
                try:
                    cache[key] = future.result()
                except Exception as exc:  # noqa: BLE001 - justified, see below
                    # Deliberately broad. :func:`tls_check` is written to convert
                    # every failure into a 3-tuple and to raise nothing, so an
                    # exception escaping it is a bug here or an environment
                    # surprise (a patched socket layer, an exhausted fd table).
                    # Letting it propagate would abort the whole stage and take
                    # every not-yet-run endpoint with it, breaking the
                    # conservation invariant that N inputs give N outputs, so
                    # the endpoint is recorded as a failure and the stage
                    # continues. Narrowing it to OSError would reintroduce
                    # exactly that poisoning on any non-socket exception.
                    #
                    # It must not vanish, though: the endpoint is recorded as a
                    # failure in the artifact AND the exception is reported
                    # through the progress log, so a systematic worker fault is
                    # visible instead of silently degrading every row to `other`.
                    slug = _oserror_slug(exc)
                    st.log(
                        f"tls: worker raised for {key[0]}:{key[1]} (sni={key[2]!r}): "
                        f"{exc!r}; recorded as {slug!r}"
                    )
                    cache[key] = (False, None, slug)
    st.advance(len(batch))

    results: list[tuple[_Entry, tuple[bool, float | None, str | None]]] = []
    for entry in batch:
        key = _cache_key(entry)
        results.append((entry, (False, None, "parse") if key is None else cache[key]))
    return results


def _cache_key(entry: _Entry) -> tuple[str, int, str | None, bool] | None:
    """Identity for the handshake cache: endpoint plus verification mode."""
    if entry.link is None:
        return None
    return (
        entry.link.host,
        entry.link.port,
        entry.link.sni,
        _insecure_requested(entry.link_text),
    )


def _insecure_requested(link_text: str) -> bool:
    """Read the link's ``allowInsecure``/``insecure`` query param.

    Verification is relaxed only when every insecure-ish param present is truthy, so a
    link carrying both ``insecure=1`` and ``allowInsecure=0`` keeps verifying rather
    than silently trusting an unverifiable certificate.

    A link that survives ``links.parse_link`` but that ``urlsplit`` still chokes on
    (malformed IPv6 literals, bad port ranges) is treated as verified, which is the
    safe default.
    """
    try:
        params = parse_qsl(urlsplit(link_text).query, keep_blank_values=True)
    except ValueError:
        return False
    values = [value for key, value in params if key.lower() in _INSECURE_KEYS]
    if not values:
        return False
    return all(value.strip().lower() in _TRUTHY for value in values)


def _record(
    entry: _Entry,
    outcome: tuple[bool, float | None, str | None],
    out_rows: list[tuple[float, str]],
    faulty_rows: list[tuple[float | None, str, str]],
) -> None:
    """Route one outcome into the success or failure buckets."""
    if entry.link is None:
        faulty_rows.append((entry.planned_ms, "parse", entry.link_text))
        return
    ok, ms, reason = outcome
    if ok and ms is not None:
        out_rows.append((ms, entry.link_text))
        return
    faulty_rows.append((ms if ms is not None else entry.planned_ms, reason or "tls", entry.link_text))


def _render(value: float) -> str:
    """Format a millisecond value for an artifact field."""
    return str(int(value)) if float(value).is_integer() else f"{value:.2f}"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the TLS stage as a script: ``python tls_test.py INPUT OUTPUT [FAULTY]``."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        return 2
    faulty = args[2] if len(args) > 2 else f"{args[1]}_faulty"
    stats = tls_runner_threaded(args[0], args[1], faulty)
    progress.summary_table(sorted(stats.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
