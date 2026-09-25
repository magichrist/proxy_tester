# Refactor Spec — proxy_tester

Binding contract for the parallel refactor. **Every agent must match this exactly.**
If something here looks wrong, still implement it, then report the concern in your final message.

## Non-negotiables

- **Python 3.10+**, **stdlib only**. `requirements.txt` stays empty. No new dependencies.
- Every module starts with `from __future__ import annotations` (so `X | None` works at runtime on 3.10).
- No bare `except:` and no bare `except Exception` around I/O that should report *why* it failed — narrow where practical, and always record the reason into the failure artifact rather than discarding it.
- No `os.system`, no `subprocess` shelling out to `sed`/`nc`/`awk`/`ping`. Pure Python.
- No per-line `print()`. Progress goes through a shared `progress.py` helper (see below).
- Docstrings on every public function. No comments that merely restate the code.
- Type-annotated signatures.

## Target file layout

| File | Owner | Status |
|---|---|---|
| `Config.py` | Agent A | rewrite (keeps `from Config import *` back-compat) |
| `links.py` | Agent A | **new** — the single source of truth for parsing |
| `progress.py` | Agent A | **new** — terminal progress reporting |
| `netprobe.py` | Agent B | **new** — replaces `nc_test.sh` + `ping_test.py` |
| `tls_test.py` | Agent C | rewrite |
| `start.py` | Agent D (wave 2) | rewrite |
| `nc_test.sh` | Agent B | **delete** |
| `ping_test.py` | Agent B | **delete** |
| `base64_decryptor.py` | Agent D (wave 2) | keep, small fixes only |
| `tests/` | Agent E (wave 2) | **new** |

## Artifact pipeline (in `output/`)

Stage suffixes are unchanged from today so existing muscle memory keeps working:

```
<name>.de                        decoded links
<name>.de.alive                  TCP-connectable endpoints
<name>.de.alive.filtered         passed the latency threshold
<name>.de.alive.filtered.tls     TLS handshake OK   -> "<ms>\t<link>" ascending
<name>.de.alive.filtered.tls_faulty   TLS failed    -> "<ms>\t<link>" or "<reason>\t<link>"
<name>.timings.jsonl             per-endpoint probe measurements
```

**`<ms>\t<link>` is the one agreed output format for scored artifacts** — milliseconds first,
single literal tab, then the *unmodified* original link. Never append `-- ms` to a link again.

`timings.jsonl` is one JSON object per line:

```json
{"endpoint": "1.2.3.4:443", "host": "1.2.3.4", "port": 443, "ok": true, "ms": 42.31, "error": null}
{"endpoint": "1.2.3.4:443", "host": "1.2.3.4", "port": 443, "ok": false, "ms": null, "error": "timeout"}
```

`error` is a short lowercase slug (`timeout`, `refused`, `dns`, `unreachable`, `tls`, `other`).

## Module APIs (exact)

### `links.py`

```python
@dataclass(frozen=True, slots=True)
class ParsedLink:
    raw: str
    scheme: str
    host: str
    port: int
    sni: str | None
    uuid: str | None
    key: str
    endpoint: tuple[str, int]

    @property
    def endpoint_str(self) -> str: ...   # f"{host}:{port}"

def parse_link(line: str) -> ParsedLink | None
def iter_raw_lines(path: str | os.PathLike[str]) -> Iterator[str]
def dedupe(lines: Iterable[str]) -> tuple[list[str], int]
    """Returns (unique_lines_in_first_seen_order, duplicate_count)."""
def load_unique(path: str | os.PathLike[str]) -> tuple[list[ParsedLink], int]:
    """Parse + dedupe + drop unparseable. Returns (links, dropped_count)."""
def filter_latency(links: Iterable[ParsedLink], timings: Mapping[str, float | None],
                   max_ms: float) -> tuple[list[ParsedLink], list[ParsedLink]]:
    """Split into (within_threshold, rejected). Unmeasured endpoints go to rejected."""
```

Parsing rules:

- Accept `scheme://[userinfo@]host[:port][/path][?query][#fragment]`.
- **Port defaults to 443 when absent.** Never drop a link for a missing port.
- Bare `host:port` and bare `host` (→ 443) are accepted.
- `ss://` with base64 userinfo: base64-decode the userinfo, then re-parse the inner
  `method:password@host:port` shape.
- `sni` comes from the `sni` query param, else the `host` query param, else the URL host.
- `key` (the dedup identity) = `scheme://uuid@host:port` + `?` + **sorted** query params,
  **excluding the fragment**. The fragment is a human note (`#EPODONIOS`) and must not
  create distinct entries. Preserve the *first-seen* raw line as the representative.
- Return `None` (never raise) for anything unparseable.

### `netprobe.py`

```python
def probe_endpoint(host: str, port: int, timeout: float) -> tuple[bool, float | None, str | None]
    """Single timed TCP connect. Returns (ok, connect_ms, error_slug)."""

def probe_file(input_file: str, alive_file: str, timings_file: str,
               *, timeout: float = ..., max_workers: int = ...) -> dict[str, int]
    """
    One TCP connect per DISTINCT endpoint; every link sharing that endpoint reuses the result.
    Writes the surviving links to alive_file, the JSONL above to timings_file.
    Returns {"links_in", "endpoints", "links_alive", "endpoints_dead", "links_dead"}.
    """

def load_timings(timings_file: str) -> dict[str, float | None]
    """endpoint_str -> connect_ms (or None if it failed)."""

def filter_by_latency(input_file: str, output_file: str, timings_file: str,
                      *, max_ms: float = ...) -> dict[str, int]
    """Rewrite the alive file keeping only links whose endpoint connected within max_ms."""
```

Notes:
- `probe_endpoint` must measure only the connect, via `time.perf_counter()` around
  `socket.create_connection`. Use `socket.getaddrinfo` failures as `dns`.
- **The cache is the whole point**: 10k links over 1k endpoints must issue ~1k connects, not 10k.
- Accept an optional pre-seeded `timings` mapping so the cache survives across stages.

### `tls_test.py`

```python
def tls_check(host: str, port: int, sni: str | None, timeout: float) -> tuple[bool, float | None, str | None]
    """(ok, handshake_ms, error_slug). NEVER return a bare bool — the old code did and
    check_link then indexed it, which is the bug being fixed."""

def tls_runner_threaded(input_file: str, output_file: str, faulty_file: str | None = None,
                        *, timeout: float = ..., max_workers: int = ...) -> dict[str, int]
    """
    input_file lines are '<ms>\t<link>' (tolerate a bare link too).
    output_file: '<ms>\t<link>' for handshakes that succeeded, ascending by ms.
    faulty_file: '<ms>\t<link>' or '<reason>\t<link>' for every failure — NOTHING is dropped.
    Returns {"tested", "ok", "failed"}.
    """
```

- `ssl.create_default_context()` (keep cert verification) — but honour the link's
  `allowInsecure`/`insecure` query param: if truthy, relax to `CERT_NONE`.
- Handshake timing wraps `wrap_socket` only, not the TCP connect.
- Cap in-flight futures (the old code submitted every line at once). Chunk the work.
- Cache by `(host, port, sni)` so duplicate endpoints cost one handshake.

### `progress.py`

```python
def stage(title: str, total: int | None = None) -> "Stage"
class Stage:
    def advance(self, n: int = 1) -> None      # throttled \r counter, no per-item prints
    def log(self, msg: str) -> None            # a handful of notable lines only
    def done(self, summary: str = "") -> None
    def __enter__(self) -> "Stage": ...
    def __exit__(self, *exc) -> None: ...
def summary_table(rows: list[tuple[str, int]]) -> None
```

Must degrade gracefully when stdout is not a TTY (fall back to periodic lines, not `\r` spam).

### `Config.py`

Keep every existing name working (`from Config import *` is used by old code and by the README):

```
PING_MAX_TIME_MS   = 800.0   # latency threshold in ms (now measured as TCP connect time)
PING_COUNT         = 1       # kept for back-compat; the TCP probe is a single sample
PING_TIMEOUT       = 1.0     # now SECONDS, unambiguously, on every platform
PING_THREADS       = 30
NC_TIMEOUT         = 1.0     # now SECONDS
NC_JOBS            = 30
TLS_TIMEOUT        = 3.0
TLS_THREADS        = 30
```

Add:
```
MAX_LATENCY_MS     = float(PING_MAX_TIME_MS)   # canonical name
PROBE_TIMEOUT      = float(NC_TIMEOUT)         # canonical name
PROBE_WORKERS      = int(NC_JOBS)              # canonical name
TOP_N              = 20                        # how many best results to highlight
```

All values are overridable at runtime from the CLI (`--set MAX_LATENCY_MS=400`) via
`def apply_overrides(pairs: Iterable[str]) -> None` which does `setattr` on this module
and re-derives the canonical aliases. Validate types and reject unknown names with a clear error.

## Correctness requirements (what "done" means)

1. `False[1]` can never happen — no union return types that are indexed without a type check.
2. A link missing its port is never dropped.
3. Every input link ends up in exactly one of: `alive`, `tls`, `tls_faulty`, or an
   explicitly-reported parse-failure count. **Silent loss is a bug.**
4. Sorted artifacts are numerically sorted by the leading ms.
5. `from Config import *` still works and the old constant names still resolve.
6. On a 10k-link input, the probe stage issues on the order of (distinct endpoints) connects.
7. Nothing shells out to external binaries.
