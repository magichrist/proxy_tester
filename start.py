#!/usr/bin/env python3
"""proxy_tester pipeline orchestrator.

Downloads (or picks up) lists of vless/vmess/trojan/ss proxy links, decodes any
base64 subscription payloads, probes every distinct endpoint with a TCP connect,
drops what is too slow, TLS-handshakes the survivors, and reports what happened
to every input line.

Every run leaves exactly one file per source in the workspace
(``output/`` by default)::

    <name>.alive        every link that passed all four stages, as
                        "<ms>\\t<link>", fastest first

That is the deliverable. The per-stage intermediates live in ``<out>/.work/``
and are deleted when the run finishes, so the workspace stays readable::

    <name>.de                  decoded links
    <name>.probe               TCP-connectable endpoints
    <name>.filtered            passed the latency threshold
    <name>.tls                 TLS handshake OK
    <name>.tls_faulty          TLS failed -> "<ms|reason>\\t<link>"
    <name>.timings.jsonl       per-endpoint probe measurements

Pass ``--keep-stages`` to retain them for debugging.

Every path is resolved relative to *this file*, never to the current working
directory, so ``python3 /path/to/start.py`` behaves identically from anywhere.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

import base64_decryptor
import Config
import links
import netprobe
import progress
import tls_test

__all__ = ["main"]

# --------------------------------------------------------------------------
# Layout
# --------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_WORKSPACE = SCRIPT_DIR / "output"
LOCAL_DIR = SCRIPT_DIR / "local"
URLS_FILE = SCRIPT_DIR / "urls.txt"

#: The one file a run leaves behind: every link that survived the whole
#: pipeline, ``<ms>\t<link>``, fastest first.
SUFFIX_OUT = ".alive"

#: Intermediates. They live in a scratch directory and are deleted at the end
#: of a run unless ``--keep-stages`` is passed, so the workspace only ever
#: shows the final result.
WORK_DIRNAME = ".work"
SUFFIX_DE = ".de"
SUFFIX_PROBE = ".probe"
SUFFIX_FILTERED = ".filtered"
SUFFIX_TLS = ".tls"
SUFFIX_FAULTY = ".tls_faulty"
SUFFIX_TIMINGS = ".timings.jsonl"

#: Artifacts that may be re-adopted as pipeline input when a run has no fresh
#: links of its own. The final output is the only thing that outlives a run, so
#: it is the only thing there is to adopt.
ADOPTABLE_SUFFIXES = (SUFFIX_OUT,)

#: Suffixes that mark a file as a pipeline artifact rather than a link list.
ARTIFACT_SUFFIXES = (
    SUFFIX_OUT,
    SUFFIX_FAULTY,
    SUFFIX_TLS,
    SUFFIX_FILTERED,
    SUFFIX_DE,
    ".jsonl",
)

#: Appended to the name of an adopted artifact so nothing is overwritten in place.
RESUME_MARKER = ".resume"

#: How much of a link the top-N listing shows before ellipsising it. Display
#: only — the published artifact always keeps the full link.
TOP_LINK_PREVIEW = 60

# --------------------------------------------------------------------------
# Download behaviour
# --------------------------------------------------------------------------

USER_AGENT = (
    "proxy_tester/2.0 (stdlib urllib; +https://github.com/magichrist/proxy_tester)"
)
DOWNLOAD_TIMEOUT = 30.0
#: Largest response accepted from a subscription source, as a runaway guard.
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

BANNER = r"""
⠀⠀⠀⢠⣾⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄⣀⣀⣤⣤⣶⣾⣿⣿⣿⡷
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⣿⣿⣿⡇⠀⡾⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀
⣿⣿⣿⣧⡀⠁⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⢹⠉⠙⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⠀⣀⣼⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠀⠤⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⠿⠋⢃⠈⠢⡁⠒⠄⡀⠈⠁⠀⠀{meow meow mf}
⣿⣿⠟⠁⠀⠀⠈⠉⠉⠁⠀⠀⠀⠀⠈⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""


# --------------------------------------------------------------------------
# Data carriers
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Source:
    """One link list queued for processing."""

    name: str
    path: Path
    origin: str


@dataclass(slots=True)
class Outcome:
    """Per-file accounting. Every input line lands in exactly one category."""

    name: str
    origin: str
    total_lines: int = 0
    parsed: int = 0
    duplicates: int = 0
    unparseable: int = 0
    endpoints: int = 0
    endpoint_dead: int = 0
    over_latency: int = 0
    tls_tested: int = 0
    tls_ok: int = 0
    tls_failed: int = 0
    decoded_blocks: int = 0
    #: The published deliverable: bare links, fastest first, no timing column.
    tls_path: Path | None = None
    #: The same links with their ``<ms>\t`` timings, kept in the scratch dir so
    #: the report and the top-N listing can still show latency.
    scored_path: Path | None = None
    sorted_ok: bool = True
    problems: list[str] = field(default_factory=list)

    def check_balance(self) -> None:
        """Record a problem for every conservation identity that does not hold."""
        load = self.duplicates + self.unparseable + self.parsed
        if load != self.total_lines:
            self.problems.append(
                f"line balance: {self.duplicates} duplicate + {self.unparseable} "
                f"unparseable + {self.parsed} parsed = {load}, expected {self.total_lines}"
            )
        mid = self.endpoint_dead + self.over_latency + self.tls_tested
        if mid != self.parsed:
            self.problems.append(
                f"parsed balance: {self.endpoint_dead} endpoint-dead + "
                f"{self.over_latency} over-latency + {self.tls_tested} tls-tested "
                f"= {mid}, expected {self.parsed}"
            )
        tls = self.tls_ok + self.tls_failed
        if tls != self.tls_tested:
            self.problems.append(
                f"tls balance: {self.tls_ok} ok + {self.tls_failed} failed = "
                f"{tls}, expected {self.tls_tested}"
            )
        if not self.sorted_ok:
            self.problems.append("tls artifact is NOT sorted ascending by ms")

    @property
    def balanced(self) -> bool:
        """True when every conservation identity held for this file."""
        return not self.problems


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------


def _is_artifact(name: str) -> bool:
    """True when ``name`` looks like a pipeline artifact rather than a link list."""
    return any(name.endswith(suffix) for suffix in ARTIFACT_SUFFIXES)


def _unique_path(directory: Path, name: str) -> Path:
    """Return a path inside ``directory`` that does not exist yet."""
    candidate = directory / name
    if not candidate.exists():
        return candidate
    stem, dot, extension = name.partition(".")
    if not dot:
        stem, extension = name, ""
    for index in range(1, 1000):
        suffix = f"{stem}_{index}" + (f".{extension}" if extension else "")
        candidate = directory / suffix
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"cannot find a free filename for {name!r} in {directory}")


def _count_lines(path: Path) -> int:
    """Count non-blank lines without loading the file into memory."""
    total = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                total += 1
    return total


def _truncate_to_limit(path: Path, limit: int) -> int:
    """Keep only the first ``limit`` non-blank lines of ``path``; return how many."""
    kept: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            kept.append(line.rstrip("\r\n"))
            if len(kept) >= limit:
                break
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for line in kept:
            handle.write(line + "\n")
    return len(kept)


def _read_scored(path: Path) -> list[tuple[float, str]]:
    """Read a ``<ms>\\t<link>`` artifact into (ms, link) pairs.

    ``maxsplit=1`` is deliberate: a link may itself contain a tab, and the
    millisecond field is always first.
    """
    rows: list[tuple[float, str]] = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue
            head, tab, rest = line.partition("\t")
            if not tab or not rest.strip():
                continue
            try:
                ms = float(head.strip())
            except ValueError:
                continue
            rows.append((ms, rest))
    return rows


# --------------------------------------------------------------------------
# Input collection
# --------------------------------------------------------------------------


_CD_STAR = re.compile(r"filename\*\s*=\s*[^']*''([^;]+)", re.IGNORECASE)
_CD_PLAIN = re.compile(r'filename\s*=\s*"([^"]+)"', re.IGNORECASE)
_CD_BARE = re.compile(r"filename\s*=\s*([^;]+)", re.IGNORECASE)
_UNSAFE_NAME = re.compile(r"[^\w.\-+=]")


def _filename_for(url: str, disposition: str, index: int) -> str:
    """Pick a safe on-disk filename for a downloaded body.

    ``Content-Disposition`` wins, then the URL path basename, then a positional
    fallback. Query strings and fragments are stripped first: several v2ray
    config repos serve a filename containing ``?`` and ``&``, which is illegal
    on some filesystems and unreadable everywhere.
    """
    raw = ""
    match = _CD_STAR.search(disposition or "")
    if match:
        raw = unquote(match.group(1))
    else:
        match = _CD_PLAIN.search(disposition or "") or _CD_BARE.search(
            disposition or ""
        )
        if match:
            raw = match.group(1)
    if not raw:
        raw = url
    raw = raw.split("#", 1)[0].split("?", 1)[0].replace("\\", "/")
    raw = os.path.basename(raw)
    name = _UNSAFE_NAME.sub("_", raw).strip("._")
    return name or f"download_{index:03d}"


def _download_one(url: str, out_dir: Path, index: int) -> Path | None:
    """Fetch one subscription URL into ``out_dir``; None on failure.

    Never raises and never aborts the run: a dead source is reported and the
    remaining sources are still attempted. No external binary is invoked.
    """
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    )
    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
            payload = response.read(MAX_DOWNLOAD_BYTES + 1)
            disposition = response.headers.get("Content-Disposition", "") or ""
            final_url = response.geturl() or url
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        progress.log(f"  download FAILED  {url}  ({reason})")
        return None

    if len(payload) > MAX_DOWNLOAD_BYTES:
        progress.log(f"  download SKIPPED {url}  (over {MAX_DOWNLOAD_BYTES:,} bytes)")
        return None

    name = _filename_for(final_url, disposition, index)
    path = _unique_path(out_dir, name)
    try:
        path.write_bytes(payload)
    except OSError as exc:
        progress.log(f"  save FAILED     {name}  ({exc})")
        return None
    progress.log(f"  ok              {name}  ({len(payload):,} bytes)  <- {url}")
    return path


def _local_has_files(local_dir: Path) -> bool:
    """True when ``local_dir`` holds at least one usable file."""
    if not local_dir.is_dir():
        return False
    return any(
        entry.is_file() and not entry.name.startswith(".")
        for entry in local_dir.iterdir()
    )


def _read_urls(urls_file: Path) -> list[str]:
    """Read the subscription list, ignoring blanks and ``#`` comments."""
    if not urls_file.exists():
        progress.log(f"  no {urls_file.name}; nothing to download")
        return []
    urls: list[str] = []
    with open(urls_file, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            urls.append(text)
    return urls


def download_inputs(urls_file: Path, out_dir: Path) -> list[Path]:
    """Download every URL in ``urls_file`` into ``out_dir``; report each result."""
    urls = _read_urls(urls_file)
    if not urls:
        return []
    progress.log(f"downloading {len(urls)} source(s) from {urls_file.name}")
    saved: list[Path] = []
    for index, url in enumerate(urls, start=1):
        path = _download_one(url, out_dir, index)
        if path is not None:
            saved.append(path)
    return saved


def copy_local_inputs(local_dir: Path, out_dir: Path) -> list[Path]:
    """Copy every file in ``local_dir`` into ``out_dir``, creating the dir if absent."""
    if not local_dir.exists():
        local_dir.mkdir(parents=True, exist_ok=True)
        progress.log(f"  created {local_dir} — drop your own link lists in here")
    if not local_dir.is_dir():
        progress.log(f"  {local_dir} is not a directory; skipping")
        return []

    copied: list[Path] = []
    for entry in sorted(local_dir.iterdir()):
        if not entry.is_file() or entry.name.startswith("."):
            continue
        target = _unique_path(out_dir, entry.name)
        try:
            shutil.copy2(entry, target)
        except OSError as exc:
            progress.log(f"  copy FAILED  {entry.name}  ({exc})")
            continue
        copied.append(target)
    progress.log(f"  copied {len(copied)} file(s) from {local_dir.name}/")
    return copied


def _resume_stem(filename: str) -> str:
    """Strip pipeline suffixes from an artifact name to recover its source name.

    A resume marker already on the name is stripped too, so re-running a
    ``--no-url`` smoke test does not creep ``.resume.resume.resume``.
    """
    name = filename
    for suffix in ADOPTABLE_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    if name.endswith(RESUME_MARKER) and len(name) > len(RESUME_MARKER):
        name = name[: -len(RESUME_MARKER)]
    return name


def select_leftovers(out_dir: Path) -> list[Path]:
    """Pick the deepest pipeline artifact per source stem, newest wins a tie.

    ``.filtered`` outranks ``.alive`` for the same stem, so a leftover always
    carries as much filtering as the previous run achieved. Pure selection: no
    copying, so the caller can run it before the workspace is wiped.
    """
    by_stem: dict[str, tuple[int, float, Path]] = {}
    if not out_dir.is_dir():
        return []
    for entry in sorted(out_dir.iterdir()):
        if not entry.is_file():
            continue
        for rank, suffix in enumerate(ADOPTABLE_SUFFIXES):
            if entry.name.endswith(suffix):
                stem = _resume_stem(entry.name)
                try:
                    mtime = entry.stat().st_mtime
                except OSError:
                    mtime = 0.0
                best = by_stem.get(stem)
                if best is None or (rank, mtime) < (best[0], best[1]):
                    by_stem[stem] = (rank, mtime, entry)
                break

    chosen: list[Path] = []
    for stem in sorted(by_stem):
        source = by_stem[stem][2]
        try:
            if _count_lines(source):
                chosen.append(source)
        except OSError:
            continue
    return chosen


def adopt_leftovers(
    out_dir: Path, staged: Sequence[tuple[str, str, Path]]
) -> list[tuple[str, str, Path]]:
    """Restore pre-staged leftovers into the workspace under their own names.

    The surviving artifact is ``<stem>.alive``, and that is exactly the name the
    run will write back to, so adoption is a straight restore: no ``.resume``
    marker, no second copy. The pipeline's intermediates live in the scratch
    directory, so the restored file is never written to until the final move.

    Returns ``(stem, origin_name, path)`` triples.
    """
    adopted: list[tuple[str, str, Path]] = []
    for stem, origin_name, staged_path in staged:
        target = out_dir / f"{stem}{SUFFIX_OUT}"
        try:
            shutil.copy2(staged_path, target)
        except OSError as exc:
            progress.log(f"  reuse FAILED  {origin_name}  ({exc})")
            continue
        try:
            count = _count_lines(target)
        except OSError:
            continue
        if not count:
            continue
        progress.log(
            f"  {progress.paint('reusing', 'cyan')} {origin_name} ({count} link(s))"
        )
        adopted.append((stem, origin_name, target))
    return adopted


def collect_inputs(
    work_dir: Path,
    leftover_dir: Path,
    local_dir: Path,
    urls_file: Path,
    do_download: bool,
    staged: Sequence[tuple[str, str, Path]] = (),
) -> tuple[list[Source], list[str]]:
    """Build the work list: downloads, then local files, then any leftovers.

    Downloads and ``local/`` copies land in ``work_dir`` so the raw inputs are
    cleaned up with the rest of the intermediates. Leftovers are rescued from
    ``leftover_dir`` (the workspace root) and are only used when neither
    downloads nor ``local/`` produced a single link list.

    Returns ``(sources, failures)``. A file that cannot even be read is a
    failure, not a silent skip: a run that processed nothing must not look like
    a clean run.
    """
    fresh: list[Path] = []
    adopted_names: set[str] = set()
    if do_download:
        fresh.extend(download_inputs(urls_file, work_dir))
    else:
        progress.log(f"{progress.paint('--no-url', 'dim')}: skipping downloads")
    fresh.extend(copy_local_inputs(local_dir, work_dir))

    if not fresh and staged:
        progress.log(
            f"{progress.paint('no new link lists', 'yellow')}; re-using the previous run's output"
        )
        rescued = adopt_leftovers(leftover_dir, staged)
        fresh.extend(path for _stem, _origin, path in rescued)
        adopted_names.update(path.name for path in fresh)

    sources: list[Source] = []
    failures: list[str] = []
    for path in fresh:
        if path.name not in adopted_names and _is_artifact(path.name):
            progress.log(f"  skipping artifact {path.name}")
            continue
        try:
            lines = _count_lines(path)
        except OSError as exc:
            message = f"{path.name}: {type(exc).__name__}: {exc}"
            failures.append(message)
            _error(f"  unreadable input: {message}")
            continue
        if lines == 0:
            progress.log(f"  skipping empty file {path.name}")
            continue
        if path.name in adopted_names:
            # A rescued <name>.alive: the run refreshes it in place, so it is
            # both the input and the output.
            sources.append(
                Source(name=_resume_stem(path.name), path=path, origin="adopted")
            )
        else:
            sources.append(Source(name=path.name, path=path, origin="input"))
    return sources, failures


# --------------------------------------------------------------------------
# Pipeline stages
# --------------------------------------------------------------------------


def process_source(
    source: Source,
    out_dir: Path,
    work_dir: Path,
    workers: int,
    limit: int | None = None,
) -> Outcome:
    """Run decode -> probe -> latency filter -> TLS for one source file.

    Every intermediate is written into ``work_dir`` and thrown away afterwards;
    the single artifact published to ``out_dir`` is ``<source>.alive`` holding
    the links that survived all four stages, fastest first.

    Each stage reads its own previous artifact, so a stage can never clobber the
    input it is about to read. ``limit`` is applied to the *decoded* link list,
    not the raw input: a subscription is often a single base64 line, and
    truncating the raw file would leave a partial payload rather than a shorter
    list.
    """
    outcome = Outcome(name=source.name, origin=source.origin)
    de_path = work_dir / f"{source.name}{SUFFIX_DE}"
    alive_path = work_dir / f"{source.name}{SUFFIX_PROBE}"
    filtered_path = work_dir / f"{source.name}{SUFFIX_FILTERED}"
    tls_path = work_dir / f"{source.name}{SUFFIX_TLS}"
    faulty_path = work_dir / f"{source.name}{SUFFIX_FAULTY}"
    timings_path = work_dir / f"{source.name}{SUFFIX_TIMINGS}"
    out_path = out_dir / f"{source.name}{SUFFIX_OUT}"

    with progress.stage(f"decode {source.name}") as st:
        stats = base64_decryptor.runner(str(source.path), str(de_path))
        outcome.decoded_blocks = stats.decoded_blocks
        if stats.decoded:
            st.log(
                f"{source.name}: {stats.lines_in} line(s) in, {stats.decoded_blocks} "
                f"base64 block(s) -> {stats.decoded_lines} link(s) out"
            )
        else:
            st.log(
                f"{source.name}: no base64 payload, {stats.lines_out} line(s) passed through"
            )
        if limit is not None and stats.lines_out > limit:
            kept = _truncate_to_limit(de_path, limit)
            st.log(
                f"{source.name}: --limit kept the first {kept} of "
                f"{stats.lines_out} link(s)"
            )

    _unique_links, load_stats = links.load_unique_detailed(str(de_path))
    outcome.total_lines = load_stats.total_lines
    outcome.parsed = load_stats.links
    outcome.duplicates = load_stats.duplicates
    outcome.unparseable = load_stats.dropped
    outcome.endpoints = load_stats.endpoints

    probe = netprobe.probe_file(
        str(de_path),
        str(alive_path),
        str(timings_path),
        timeout=float(Config.PROBE_TIMEOUT),
        max_workers=workers,
    )
    outcome.endpoint_dead = int(probe["links_dead"])

    timings = netprobe.load_timings(str(timings_path))
    filtered = netprobe.filter_by_latency(
        str(alive_path),
        str(filtered_path),
        str(timings_path),
        max_ms=float(Config.MAX_LATENCY_MS),
        timings=timings,
    )
    outcome.over_latency = int(filtered["rejected"])

    tls_stats = tls_test.tls_runner_threaded(
        str(filtered_path),
        str(tls_path),
        str(faulty_path),
        timeout=float(Config.TLS_TIMEOUT),
        max_workers=workers,
    )
    outcome.tls_tested = int(tls_stats["tested"])
    outcome.tls_ok = int(tls_stats["ok"])
    outcome.tls_failed = int(tls_stats["failed"])

    outcome.sorted_ok, _rows = assert_sorted(tls_path)
    outcome.scored_path = tls_path

    written = _strip_timings(tls_path, out_path)
    outcome.tls_path = out_path
    if written != outcome.tls_ok:
        outcome.problems.append(
            f"published {written} link(s) but the TLS stage reported {outcome.tls_ok}"
        )

    outcome.check_balance()
    return outcome


def _strip_timings(scored: Path, out_path: Path) -> int:
    """Write the bare links of a ``<ms>\\t<link>`` artifact to ``out_path``.

    The deliverable is a clean link list a client can import directly, so the
    latency column is dropped here rather than in every consumer. Order is
    preserved, so the file is still fastest-first. A link that itself contains a
    tab is unaffected: only the first field is removed, via ``maxsplit=1``.
    """
    count = 0
    with (
        open(scored, "r", encoding="utf-8", errors="replace") as src,
        open(out_path, "w", encoding="utf-8", newline="\n") as dst,
    ):
        for raw_line in src:
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue
            head, tab, link = line.partition("\t")
            if tab and link.strip():
                try:
                    float(head.strip())
                except ValueError:
                    dst.write(line + "\n")
                    count += 1
                    continue
                dst.write(link + "\n")
            else:
                dst.write(line + "\n")
            count += 1
    return count


def assert_sorted(path: Path) -> tuple[bool, list[tuple[float, str]]]:
    """Return whether a ``<ms>\\t<link>`` artifact is numerically ascending.

    Cheap, and it makes the historical "artifact is silently unsorted" bug
    impossible to reintroduce without the run saying so.
    """
    rows = _read_scored(path)
    previous: float | None = None
    for index, (ms, _link) in enumerate(rows):
        if previous is not None and ms < previous:
            progress.log(
                f"  SORT VIOLATION in {path.name}: line {index + 1} has {ms} ms "
                f"after {previous} ms"
            )
            return False, rows
        previous = ms
    return True, rows


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _totals(outcomes: Sequence[Outcome]) -> Outcome:
    """Sum the per-file outcomes into one row for the summary table."""
    total = Outcome(name="TOTAL", origin="")
    for item in outcomes:
        total.total_lines += item.total_lines
        total.parsed += item.parsed
        total.duplicates += item.duplicates
        total.unparseable += item.unparseable
        total.endpoints += item.endpoints
        total.endpoint_dead += item.endpoint_dead
        total.over_latency += item.over_latency
        total.tls_tested += item.tls_tested
        total.tls_ok += item.tls_ok
        total.tls_failed += item.tls_failed
        total.sorted_ok = total.sorted_ok and item.sorted_ok
        total.problems.extend(item.problems)
    total.check_balance()
    return total


def report(outcomes: Sequence[Outcome], elapsed: float) -> int:
    """Print the final report; return the process exit code."""
    paint = progress.paint
    progress.log("")
    progress.log(
        f"=== {paint('run summary', 'bold')} ({paint(f'{elapsed:.1f}s', 'dim')}) ==="
    )
    _table(outcomes)

    total = _totals(outcomes)
    progress.log("")
    progress.log(f"=== {paint('stage inputs', 'bold')} ===")
    for item in outcomes:
        progress.log(
            f"  {item.name}: {paint(f'{item.endpoints} distinct endpoint(s) probed', 'bold')}, "
            f"{item.decoded_blocks} base64 block(s) decoded"
        )

    progress.log("")
    progress.log(f"=== {paint('conservation', 'bold')} ===")
    identities = (
        (
            "line balance",
            f"{total.total_lines} in  =  {total.duplicates} duplicate + "
            f"{total.unparseable} unparseable + {total.parsed} parsed",
        ),
        (
            "parsed balance",
            f"{total.parsed} parsed  =  {total.endpoint_dead} endpoint-dead + "
            f"{total.over_latency} over-latency + {total.tls_tested} tls-tested",
        ),
        (
            "tls balance",
            f"{total.tls_tested} tested  =  {paint(f'{total.tls_ok} ok', 'green')} + "
            f"{total.tls_failed} failed",
        ),
    )
    for name, text in identities:
        progress.log(f"  {paint(f'{name:<16}', 'dim')} {text}")

    progress.log("")
    progress.log(f"=== {paint('artifacts', 'bold')} ===")
    for item in outcomes:
        if item.tls_path is None:
            continue
        mark = (
            paint("sorted ascending", "green")
            if item.sorted_ok
            else paint("NOT SORTED", "red")
        )
        progress.log(f"  {paint(item.tls_path.name, 'bold')}: {mark}")
    if total.sorted_ok:
        progress.log(f"  {paint('sorted check: PASS', 'green')} (every ms <= the next)")
    else:
        _error(
            f"  {paint('sorted check: FAIL', 'red')} — artifact is not numerically ascending"
        )

    if total.problems:
        _error("")
        _error(
            paint(
                "!!! ACCOUNTING MISMATCH — links may have been lost silently !!!",
                "red",
                "bold",
            )
        )
        for problem in total.problems:
            _error(f"  - {problem}")
        return EXIT_FAILED

    progress.log("")
    progress.log(
        f"  {paint('✔', 'green')} conservation: every input link is accounted for exactly once"
    )
    return EXIT_OK


def _table(outcomes: Sequence[Outcome]) -> None:
    """Print the per-file outcome table with the seven required categories.

    Every cell is padded first and coloured afterwards, so the ANSI codes cannot
    disturb the column alignment.
    """
    paint = progress.paint
    columns = (
        ("source", 26, "<"),
        ("in", 7, ">"),
        ("parsed", 7, ">"),
        ("dup", 6, ">"),
        ("unparse", 8, ">"),
        ("dead", 6, ">"),
        ("slow", 6, ">"),
        ("tls_ok", 7, ">"),
        ("tls_fail", 9, ">"),
    )
    plain_width = sum(width for _label, width, _align in columns) + len(columns) - 1

    def row(cells: Sequence[str], styles: Sequence[str]) -> str:
        parts = [
            paint(f"{cell:{align}{width}}", style)
            for cell, (_label, width, align), style in zip(cells, columns, styles)
        ]
        return "  " + " ".join(parts)

    progress.log(row([label for label, _w, _a in columns], ["bold"] * len(columns)))
    progress.log("  " + paint("-" * plain_width, "dim"))

    for item in outcomes:
        progress.log(
            row(
                (
                    item.name[:26],
                    f"{item.total_lines:,}",
                    f"{item.parsed:,}",
                    f"{item.duplicates:,}",
                    f"{item.unparseable:,}",
                    f"{item.endpoint_dead:,}",
                    f"{item.over_latency:,}",
                    f"{item.tls_ok:,}",
                    f"{item.tls_failed:,}",
                ),
                (
                    "",
                    "",
                    "",
                    "",
                    "red" if item.unparseable else "",
                    "",
                    "yellow" if item.over_latency else "",
                    "green",
                    "red" if item.tls_failed else "",
                ),
            )
        )

    total = _totals(outcomes)
    progress.log("  " + paint("-" * plain_width, "dim"))
    progress.log(
        row(
            (
                "TOTAL",
                f"{total.total_lines:,}",
                f"{total.parsed:,}",
                f"{total.duplicates:,}",
                f"{total.unparseable:,}",
                f"{total.endpoint_dead:,}",
                f"{total.over_latency:,}",
                f"{total.tls_ok:,}",
                f"{total.tls_failed:,}",
            ),
            ("bold", "", "", "", "", "", "", "green", ""),
        )
    )


def _abbreviate(link: str, limit: int = TOP_LINK_PREVIEW) -> str:
    """Shorten a link for on-screen display only.

    The published artifact always keeps the full link; this is purely so a
    ranking table stays readable instead of wrapping across a dozen lines.
    """
    if len(link) <= limit:
        return link
    return link[:limit] + "..."


def top_links(outcomes: Sequence[Outcome], count: int) -> None:
    """Highlight the ``count`` fastest TLS-passing links of the run."""
    if count <= 0:
        return
    combined: list[tuple[float, str]] = []
    for item in outcomes:
        if item.scored_path is None or not item.sorted_ok:
            continue
        combined.extend(_read_scored(item.scored_path))
    combined.sort(key=lambda row: row[0])
    if not combined:
        progress.log("")
        progress.log("no TLS-passing links to highlight")
        return
    shown = combined[:count]
    progress.log("")
    progress.log(
        f"=== {progress.paint(f'top {len(shown)} fastest TLS-passing', 'bold')} ==="
    )
    for rank, (ms, link) in enumerate(shown, start=1):
        progress.log(
            f"  {progress.paint(f'{rank:>2}.', 'dim')} "
            f"{progress.paint(f'{ms:>9.2f} ms', 'green')}  {_abbreviate(link)}"
        )


def _error(message: str) -> None:
    """Write a line to stderr so failures survive a redirected stdout."""
    print(message, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


EPILOG = """\
examples:
  python3 start.py                              download + process everything
  python3 start.py --no-url --limit 300         smoke test local/ only
  python3 start.py --no-url --limit 300 --top 5 tighten the report
  python3 start.py --set MAX_LATENCY_MS=300 --set PROBE_TIMEOUT=2.0
  python3 start.py --out /tmp/probe_run --keep keep the previous workspace

notes:
  * every path is resolved relative to this file, not the current directory.
  * --set is applied first; the shorthand flags then win over it.
  * with no downloads and an empty local/, pipeline leftovers in the workspace
    are re-used as inputs (copied to "<name>.resume" first, never overwritten).
"""


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with every flag documented in --help."""
    parser = argparse.ArgumentParser(
        prog="start.py",
        description=(
            "Download proxy link lists, probe every endpoint, and rank the "
            "survivors by TLS handshake speed."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--no-url",
        action="store_true",
        help="skip URL downloads and use only local/ (and any workspace leftovers)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="process only the first N links of every input file (smoke tests)",
    )
    parser.add_argument(
        "--top",
        type=int,
        metavar="N",
        help="how many of the best results to highlight (default: Config.TOP_N)",
    )
    parser.add_argument(
        "--set",
        dest="overrides",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "override a Config setting, repeatable; e.g. "
            "--set MAX_LATENCY_MS=300 (unknown keys and bad values are rejected)"
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        metavar="N",
        help="probe and TLS concurrency (sets Config PROBE_WORKERS and TLS_THREADS)",
    )
    parser.add_argument(
        "--max-latency",
        type=float,
        metavar="MS",
        help="latency threshold in ms (shorthand for --set MAX_LATENCY_MS=MS)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="do not wipe the output directory before running (default: wipe)",
    )
    parser.add_argument(
        "--keep-stages",
        action="store_true",
        help=(
            "keep the per-stage intermediates in <out>/.work/ for debugging "
            "(default: delete them, leaving only the final <source>.alive)"
        ),
    )
    color_group = parser.add_mutually_exclusive_group()
    color_group.add_argument(
        "--color",
        dest="color",
        action="store_true",
        default=None,
        help="force ANSI colour even when stdout is not a terminal",
    )
    color_group.add_argument(
        "--no-color",
        dest="color",
        action="store_false",
        help="disable ANSI colour (also honours the NO_COLOR environment variable)",
    )
    parser.add_argument(
        "--out",
        metavar="DIR",
        help="workspace directory (default: output/ next to this script)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the banner and the active-config dump (for CI/pipes)",
    )
    return parser


def apply_settings(args: argparse.Namespace) -> int:
    """Apply ``--set`` then the shorthand flags; return an exit code."""
    progress.set_color(args.color)

    try:
        if args.overrides:
            Config.apply_overrides(args.overrides)
    except ValueError as exc:
        _error(f"error: bad --set value: {exc}")
        return EXIT_USAGE

    shorthand: list[str] = []
    if args.max_latency is not None:
        if args.max_latency < 0:
            _error(
                f"error: --max-latency must not be negative (got {args.max_latency})"
            )
            return EXIT_USAGE
        shorthand.append(f"MAX_LATENCY_MS={args.max_latency:g}")
    if args.workers is not None:
        if args.workers < 1:
            _error(f"error: --workers must be at least 1 (got {args.workers})")
            return EXIT_USAGE
        shorthand.append(f"PROBE_WORKERS={args.workers}")
        shorthand.append(f"TLS_THREADS={args.workers}")
    if args.top is not None:
        if args.top < 0:
            _error(f"error: --top must not be negative (got {args.top})")
            return EXIT_USAGE
        shorthand.append(f"TOP_N={args.top}")
    if shorthand:
        try:
            Config.apply_overrides(shorthand)
        except ValueError as exc:  # pragma: no cover - guarded above
            _error(f"error: bad flag value: {exc}")
            return EXIT_USAGE
    return EXIT_OK


def reset_workspace(out_dir: Path, keep: bool) -> None:
    """Create the workspace, wiping it first unless ``keep``."""
    if out_dir.exists() and not keep:
        progress.log(f"{progress.paint('cleaning workspace', 'dim')} {out_dir}")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the whole pipeline; see ``--help`` for the flags."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 1:
        _error(f"error: --limit must be at least 1 (got {args.limit})")
        return EXIT_USAGE

    status = apply_settings(args)
    if status != EXIT_OK:
        return status

    if not args.quiet:
        print(BANNER)
        print(Config.describe())
        print()

    out_dir = Path(args.out).expanduser().resolve() if args.out else DEFAULT_WORKSPACE

    progress.log(f"{progress.paint('workspace:', 'bold')} {out_dir}")
    progress.log(f"{progress.paint('local dir:', 'bold')} {LOCAL_DIR}")
    started = time.monotonic()

    # Leftovers must be rescued before the wipe, but they are only worth
    # rescuing when nothing else can supply input, so ask local/ and urls.txt
    # first.
    rescue = (
        (not args.no_url) or _local_has_files(LOCAL_DIR) or bool(_read_urls(URLS_FILE))
    )
    with tempfile.TemporaryDirectory(prefix="proxy_tester_leftovers_") as scratch:
        staged: list[tuple[str, str, Path]] = []
        if rescue:
            scratch_dir = Path(scratch)
            for source in select_leftovers(out_dir):
                stem = _resume_stem(source.name)
                try:
                    copy = scratch_dir / f"{stem}{SUFFIX_OUT}"
                    shutil.copy2(source, copy)
                except OSError as exc:
                    progress.log(f"  rescue FAILED {source.name} ({exc})")
                    continue
                staged.append((stem, source.name, copy))

        try:
            reset_workspace(out_dir, args.keep)
            work_dir = out_dir / WORK_DIRNAME
            work_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _error(f"error: cannot prepare workspace {out_dir}: {exc}")
            return EXIT_FAILED

        sources, failures = collect_inputs(
            work_dir, out_dir, LOCAL_DIR, URLS_FILE, not args.no_url, staged
        )

    if not sources:
        _error(
            "error: no input link lists. Add files to local/, add URLs to "
            "urls.txt, or drop --no-url."
        )
        return EXIT_FAILED

    progress.log(f"processing {len(sources)} source file(s)")
    outcomes: list[Outcome] = []
    for source in sources:
        try:
            outcomes.append(
                process_source(
                    source, out_dir, work_dir, int(Config.PROBE_WORKERS), args.limit
                )
            )
        except Exception as exc:  # one bad file must not lose the other results
            failures.append(f"{source.name}: {type(exc).__name__}: {exc}")
            _error(f"error: {failures[-1]}")

    if not outcomes:
        _error("error: every input file failed; nothing to report")
        for failure in failures:
            _error(f"  - {failure}")
        return EXIT_FAILED

    elapsed = time.monotonic() - started
    status = report(outcomes, elapsed)
    top = int(args.top) if args.top is not None else int(Config.TOP_N)
    top_links(outcomes, top)

    if failures:
        _error("")
        _error(f"warning: {len(failures)} source file(s) failed:")
        for failure in failures:
            _error(f"  - {failure}")
        if status == EXIT_OK:
            status = EXIT_FAILED

    if args.keep_stages:
        progress.log(f"{progress.paint('stages kept in', 'dim')} {work_dir}")
    else:
        shutil.rmtree(work_dir, ignore_errors=True)

    progress.log("")
    for outcome in outcomes:
        if outcome.tls_path is not None:
            progress.log(f"  {outcome.tls_path}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
