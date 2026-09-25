"""Pure-Python TCP-connect prober. Replaces the old ``nc_test.sh`` + ``ping_test.py``.

Why TCP connect instead of ICMP ``ping``: most of these endpoints are Cloudflare/CDN
anycast addresses, so ICMP measures you-to-edge rather than the proxy, and many edges
drop ICMP entirely (good proxies get reported "unreachable"). A TCP connect is also
directly meaningful: if the connect succeeds, the proxy is reachable.

The whole point of this module is the measurement cache: one TCP connect per DISTINCT
``(host, port)`` endpoint, reused by every link that shares it. On the project's real
data that turns ~10,000 connects into ~1,000.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import ssl
import sys
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, TextIO

try:  # Agent A owns this module; netprobe must import cleanly without it.
    from progress import log as _progress_log
    from progress import paint as _paint
    from progress import stage as _progress_stage
except ImportError:  # pragma: no cover - degraded path, exercised in unit tests
    _progress_log = None  # type: ignore[assignment]
    _progress_stage = None  # type: ignore[assignment]

    def _paint(text: str, *styles: str) -> str:  # type: ignore[misc]
        return text


try:  # Agent A owns this module; see _require_links().
    import links as _links
except ImportError:  # pragma: no cover - degraded path, exercised in unit tests
    _links = None  # type: ignore[assignment]

try:
    import Config as _Config
except ImportError:  # pragma: no cover - Config is always present in-tree
    _Config = None  # type: ignore[assignment]

__all__ = [
    "endpoint_str",
    "filter_by_latency",
    "load_timings",
    "probe_endpoint",
    "probe_file",
]

_ERR_UNREACHABLE = frozenset({errno.EHOSTUNREACH, errno.ENETUNREACH})


class _StderrStage:
    """Stand-in used when ``progress.py`` is unavailable.

    ``advance`` is intentionally silent: no per-item output. Only the handful of
    notable ``log`` lines are emitted, and they go to stderr so they never
    contaminate a piped artifact.
    """

    def advance(self, n: int = 1) -> None:
        return None

    def log(self, msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)

    def __enter__(self) -> _StderrStage:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _stage(title: str, total: int | None = None) -> _StderrStage | Any:
    if _progress_stage is None:
        return _StderrStage()
    return _progress_stage(title, total)


def _notable(msg: str) -> None:
    """Emit one summary line through progress.py, or stderr when it is absent."""
    if _progress_log is None:
        print(msg, file=sys.stderr, flush=True)
    else:
        _progress_log(msg)


def _require_links() -> Any:
    if _links is None:
        raise RuntimeError(
            "links.py is not importable; it owns link parsing and is required "
            "by probe_file()/filter_by_latency(). Import netprobe before links.py "
            "is written and those two functions will raise this instead of "
            "silently guessing endpoints."
        )
    return _links


def _config(name: str, *legacy: str, default: Any) -> Any:
    if _Config is not None:
        for candidate in (name, *legacy):
            value = getattr(_Config, candidate, None)
            if value is not None:
                return value
    return default


def _resolve_timeout(timeout: float | None) -> float:
    if timeout is not None:
        return float(timeout)
    return float(_config("PROBE_TIMEOUT", "NC_TIMEOUT", default=1.0))


def _resolve_workers(max_workers: int | None) -> int:
    if max_workers is not None:
        return max(1, int(max_workers))
    return max(1, int(_config("PROBE_WORKERS", "NC_JOBS", default=30)))


def _resolve_max_ms(max_ms: float | None) -> float:
    if max_ms is not None:
        return float(max_ms)
    return float(_config("MAX_LATENCY_MS", "PING_MAX_TIME_MS", default=800.0))


def _endpoint_key(host: str, port: int) -> str:
    """Render the ``host:port`` cache key, bracketing IPv6 literals.

    A byte-identical reimplementation of ``links._endpoint_key``; the two must
    never drift, because this side writes the ``timings.jsonl`` keys and the
    links side reads them back to join measurements onto links.
    """
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def endpoint_str(host: str, port: int) -> str:
    """Return the ``host:port`` cache key; IPv6 literals are bracketed.

    Renders ``1.2.3.4:443``, ``example.com:443`` and ``[2606:4700::1]:443``.
    Deliberately identical to ``links.ParsedLink.endpoint_str`` so the in-memory
    cache and the on-disk ``timings.jsonl`` keys can never drift apart; run
    ``python3 netprobe.py`` to re-verify that equality.
    """
    return _endpoint_key(host, port)


def _link_endpoint(link: Any) -> tuple[str, int]:
    endpoint = getattr(link, "endpoint", None)
    if endpoint is not None:
        host, port = endpoint
        return str(host), int(port)
    return str(link.host), int(link.port)


def probe_endpoint(
    host: str, port: int, timeout: float
) -> tuple[bool, float | None, str | None]:
    """Single timed TCP connect. Returns ``(ok, connect_ms, error_slug)``.

    Only the connect is measured: the timer wraps ``socket.create_connection``
    exclusively, so the reported value is TCP handshake latency and nothing else.

    Never raises. Every failure path yields a 3-tuple whose second element is
    ``None`` and whose third element is a short lowercase slug drawn from
    ``dns`` / ``refused`` / ``timeout`` / ``unreachable`` / ``tls`` / ``other``.
    """
    started = time.perf_counter()
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
    except socket.gaierror:
        return (False, None, "dns")
    except ssl.SSLError:
        return (False, None, "tls")
    except ConnectionRefusedError:
        return (False, None, "refused")
    except TimeoutError:
        return (False, None, "timeout")
    except OSError as exc:
        code = exc.errno
        if code == errno.ECONNREFUSED:
            return (False, None, "refused")
        if code == errno.ETIMEDOUT:
            return (False, None, "timeout")
        if code in _ERR_UNREACHABLE:
            return (False, None, "unreachable")
        return (False, None, "other")
    except Exception:
        return (False, None, "other")

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    try:
        conn.close()
    except OSError:
        pass
    return (True, round(elapsed_ms, 2), None)


def _read_jsonl(path: str) -> TextIO:
    return open(path, "r", encoding="utf-8", errors="replace")


def _write_jsonl(
    fh: TextIO,
    host: str,
    port: int,
    ok: bool,
    ms: float | None,
    error: str | None,
) -> None:
    fh.write(
        json.dumps(
            {
                "endpoint": endpoint_str(host, port),
                "host": host,
                "port": port,
                "ok": ok,
                "ms": ms,
                "error": error,
            },
            separators=(",", ":"),
        )
        + "\n"
    )


def probe_file(
    input_file: str,
    alive_file: str,
    timings_file: str,
    *,
    timeout: float | None = None,
    max_workers: int | None = None,
    timings: Mapping[str, float | None] | None = None,
) -> dict[str, int]:
    """One TCP connect per DISTINCT endpoint; every link sharing that endpoint reuses the result.

    Writes the surviving links to ``alive_file`` (input order preserved, each line the
    unmodified original link) and one JSON object per endpoint to ``timings_file``:
    ``{"endpoint","host","port","ok","ms","error"}``.

    ``timings`` optionally pre-seeds the measurement cache, keyed by
    :func:`endpoint_str` (``host:port``, IPv6 bracketed) to connect-ms-or-None.
    A key that is present is trusted and never
    re-measured; a key that is absent is probed. This is what lets the cache survive
    across pipeline stages instead of being rebuilt. Note that the pre-seeded mapping
    carries no error slugs, so a pre-seeded *failure* is written back out as the
    in-vocabulary slug ``"other"``.

    ``timeout``/``max_workers``/``max_ms`` default to ``None``, meaning "read the
    current value out of Config". They are resolved at call time rather than bound
    as argument defaults so that ``Config.apply_overrides()`` from the CLI takes
    effect on calls made after the override.

    Returns ``{"links_in", "endpoints", "links_alive", "endpoints_dead",
    "links_dead"}``. ``links_in`` counts parsed-and-deduplicated links; unparseable
    lines are excluded from it and are reported on the ``probe:`` summary line rather
    than silently dropped. Duplicate lines are already collapsed by
    ``links.load_unique`` and are not separately counted.
    """
    links_mod = _require_links()
    timeout = _resolve_timeout(timeout)
    workers = _resolve_workers(max_workers)

    parsed, dropped = links_mod.load_unique(input_file)
    total_links = len(parsed)

    endpoints: dict[str, tuple[str, int]] = {}
    for link in parsed:
        host, port = _link_endpoint(link)
        endpoints.setdefault(endpoint_str(host, port), (host, port))

    seed: Mapping[str, float | None] = timings or {}
    pending: list[tuple[str, int]] = []
    ms_by_key: dict[str, float | None] = {}
    err_by_key: dict[str, str | None] = {}

    for key, endpoint in endpoints.items():
        if key in seed:
            cached = seed[key]
            ms = float(cached) if cached is not None else None
            ms_by_key[key] = ms
            err_by_key[key] = None if ms is not None else "other"
        else:
            pending.append(endpoint)

    chunk = max(workers * 4, 1)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        with _stage(f"probing {len(endpoints)} endpoints", len(endpoints)) as st:
            for start in range(0, len(pending), chunk):
                futures = {
                    executor.submit(
                        probe_endpoint, endpoint[0], endpoint[1], timeout
                    ): endpoint
                    for endpoint in pending[start : start + chunk]
                }
                for future in as_completed(futures):
                    host, port = futures[future]
                    _ok, ms, error = future.result()
                    key = endpoint_str(host, port)
                    ms_by_key[key] = ms
                    err_by_key[key] = error
                    st.advance()

    alive_keys = {key for key, ms in ms_by_key.items() if ms is not None}

    os.makedirs(os.path.dirname(os.path.abspath(alive_file)) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(timings_file)) or ".", exist_ok=True)

    links_alive = 0
    with open(alive_file, "w", encoding="utf-8") as fh:
        for link in parsed:
            host, port = _link_endpoint(link)
            if endpoint_str(host, port) in alive_keys:
                fh.write(link.raw + "\n")
                links_alive += 1

    with open(timings_file, "w", encoding="utf-8") as fh:
        for key, (host, port) in endpoints.items():
            ms = ms_by_key[key]
            _write_jsonl(fh, host, port, ms is not None, ms, err_by_key[key])

    endpoints_dead = len(endpoints) - len(alive_keys)
    stats = {
        "links_in": total_links,
        "endpoints": len(endpoints),
        "links_alive": links_alive,
        "endpoints_dead": endpoints_dead,
        "links_dead": total_links - links_alive,
    }
    _notable(
        f"{_paint('probe:', 'bold')} {_paint(f'{links_alive}/{total_links}', 'green')} links alive "
        f"over {len(endpoints)} endpoints ({endpoints_dead} dead); "
        f"{dropped} unparseable line(s) excluded"
    )
    return stats


def load_timings(timings_file: str) -> dict[str, float | None]:
    """``endpoint_str`` -> connect_ms, or None if that endpoint failed.

    A missing file yields an empty mapping rather than raising, so a fresh workspace
    does not explode; callers that treat "empty" as "nothing was ever measured" (such
    as :func:`filter_by_latency`) check for that themselves and refuse to proceed.
    """
    result: dict[str, float | None] = {}
    if not os.path.exists(timings_file):
        return result
    with _read_jsonl(timings_file) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            key = record.get("endpoint")
            if not isinstance(key, str):
                continue
            ms = record.get("ms")
            result[key] = float(ms) if isinstance(ms, (int, float)) else None
    return result


def filter_by_latency(
    input_file: str,
    output_file: str,
    timings_file: str,
    *,
    max_ms: float | None = None,
    timings: Mapping[str, float | None] | None = None,
) -> dict[str, int]:
    """Rewrite the alive file keeping only links whose endpoint connected within ``max_ms``.

    Reads measurements from ``timings`` when given, otherwise from ``timings_file``.
    Unmeasured endpoints are treated as rejected, per ``links.filter_latency``.

    Raises ``ValueError`` if there is work to do but no measurements at all: an empty
    timings source would otherwise reject every link and silently truncate the alive
    file to nothing.

    Returns ``{"links_in", "kept", "rejected", "links_dropped"}``.
    """
    links_mod = _require_links()
    max_ms = _resolve_max_ms(max_ms)

    measurements: Mapping[str, float | None] = (
        timings if timings is not None else load_timings(timings_file)
    )
    parsed, dropped = links_mod.load_unique(input_file)
    total_links = len(parsed)

    if total_links and not measurements:
        raise ValueError(
            f"no measurements available from {timings_file!r}; "
            f"cannot latency-filter {total_links} link(s) without running probe_file first"
        )

    kept, rejected = links_mod.filter_latency(parsed, measurements, max_ms)

    os.makedirs(os.path.dirname(os.path.abspath(output_file)) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as fh:
        fh.writelines(link.raw + "\n" for link in kept)

    with _stage(f"latency <= {max_ms:g} ms", len(parsed)) as st:
        st.advance(len(kept))
    _notable(
        f"latency filter: kept {len(kept)}/{total_links} "
        f"({len(rejected)} over {max_ms:g} ms, {dropped} unparseable)"
    )

    return {
        "links_in": total_links,
        "kept": len(kept),
        "rejected": len(rejected),
        "links_dropped": dropped,
    }


def _selfcheck() -> int:
    """Assert ``endpoint_str`` stays byte-identical to ``links.ParsedLink``.

    The two renderers are separate implementations, so nothing but a check stops
    them drifting apart -- and if they do, every IPv6 endpoint silently loses its
    timing and is dropped by the latency filter. Run with ``python3 netprobe.py``.
    """
    if _links is None:
        print("selfcheck: links.py is not importable; cannot verify", file=sys.stderr)
        return 2
    hosts = [
        "1.2.3.4",
        "example.com",
        "2606:4700::1",
        "::1",
        "2001:db8:85a3::8a2e:370:7334",
        "0:0:0:0:0:0:0:1",
        "127.0.0.1",
        "sub.domain.example.co.uk",
        "xn--80ak6aa92e.com",
    ]
    ports = [443, 80, 1, 65535]
    checked = 0
    for host in hosts:
        for port in ports:
            authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            lines = [
                f"{_links.BARE_HOST_SCHEME}://{authority}",  # IPv4 / hostname / bracketed IPv6
                authority,  # bare host:port
            ]
            for line in lines:
                parsed = _links.parse_link(line)
                if parsed is None:
                    print(f"selfcheck: could not reparse {line!r}", file=sys.stderr)
                    return 2
                mine, theirs = endpoint_str(host, port), parsed.endpoint_str
                assert theirs == mine, (line, mine, theirs)
                assert mine.encode() == theirs.encode(), (line, mine, theirs)
                checked += 1
    print(
        f"selfcheck: endpoint_str identical in both modules for {checked} "
        f"host/port x input-shape combinations"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - manual invariant check
    raise SystemExit(_selfcheck())
