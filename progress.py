"""Terminal progress reporting for long-running stages.

The tool used to print one line per link, which produced ~10k lines of noise
that no one could read. This module replaces that with a single throttled
in-place counter on a terminal and an occasional sparse line when stdout is a
pipe or a CI log.

Nothing here is a progress *bar* in the dependency sense: no external packages,
no ANSI colour libraries, no cursor-position queries. A plain ANSI erase is used
and only when stdout is a real terminal.

All output goes to stdout, so callers that write artifacts to stdout should
instead run the pipeline with stdout redirected.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections.abc import Sequence
from typing import IO

__all__ = [
    "Stage",
    "color_enabled",
    "log",
    "paint",
    "set_color",
    "stage",
    "summary_table",
]

#: At most this many in-place redraws per second on a terminal.
REDRAW_INTERVAL = 1.0 / 15.0
#: On a non-TTY, emit a line each time the percentage crosses a multiple of this.
NON_TTY_STEP = 25
#: On a non-TTY with an unknown total, emit a line every this many items.
NON_TTY_CHUNK = 100
_ERASE = "\r"
_CLEAR = "\x1b[2K"

# --------------------------------------------------------------------------
# Colour
# --------------------------------------------------------------------------

RESET = "\x1b[0m"
BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
BLUE = "34"
MAGENTA = "35"
CYAN = "36"

_CODES = {
    "bold": BOLD,
    "dim": DIM,
    "red": RED,
    "green": GREEN,
    "yellow": YELLOW,
    "blue": BLUE,
    "magenta": MAGENTA,
    "cyan": CYAN,
}

#: ``None`` means "decide from the environment"; set to force a mode.
_color_override: bool | None = None


def set_color(enabled: bool | None) -> None:
    """Force colour on/off, or pass ``None`` to decide from the environment.

    Resolution order when ``None``: an explicit :data:`os.environ` setting wins,
    otherwise colour is used only on a terminal.
    """
    global _color_override
    _color_override = enabled


def color_enabled() -> bool:
    """Whether ANSI styling should be emitted.

    Off for a pipe, a CI log, or a redirected stdout, so a captured run stays
    clean. Honours the ``NO_COLOR`` and ``FORCE_COLOR`` conventions.
    """
    if _color_override is not None:
        return _color_override
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    return _is_tty(_stream())


def paint(text: str, *styles: str) -> str:
    """Wrap ``text`` in ANSI styles, or return it unchanged when colour is off.

    Only the SGR codes are counted as characters, so callers should pad the
    *plain* text and style the result — that is what keeps columns aligned.
    """
    if not styles or not color_enabled():
        return text
    codes = ";".join(_CODES[name] for name in styles if name in _CODES)
    if not codes:
        return text
    return f"\x1b[{codes}m{text}{RESET}"


def _stream() -> IO[str]:
    return sys.stdout


def _is_tty(stream: IO[str]) -> bool:
    """Return True when ``stream`` is an interactive terminal."""
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(text: str) -> int:
    """Length of ``text`` as the terminal draws it, ignoring SGR sequences.

    Padding an in-place redraw with the raw length would leave a gap wherever a
    colour code was present, and the shorter next line would then be padded
    wrongly in turn.
    """
    return len(_ANSI_RE.sub("", text))


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m{rest:04.1f}s"
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours}h{minutes:02d}m{rest:04.1f}s"


def _write(stream: IO[str], text: str) -> None:
    """Write ``text`` to ``stream``, tolerating a stream that has gone away.

    Every write in this module goes through here. A run whose stdout is a
    closed pipe -- ``proxy_tester | head``, or a CI job whose reader died --
    must lose its progress lines, not its work, so ``OSError`` (broken pipe)
    and ``ValueError`` (a stream closed underneath us, which is what ``io``
    raises) are both swallowed. Guarding only the flush, as this module used
    to for the free functions, is not enough: it is the *write* that raises
    first on a full pipe buffer.
    """
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError):
        pass


class Stage:
    """One named unit of work, rendered as a single throttled line.

    Usable as a context manager; on exit any unfinished stage is closed out with
    a final line, so a stage can never leave a half-drawn line behind::

        with stage("Probing", total=len(links)) as st:
            for link in links:
                handle(link)
                st.advance()

    :meth:`done` is the single owner of the last line, on a terminal and on a
    pipe alike. :meth:`advance` therefore never emits the completed state: that
    is what makes the final line appear exactly once, carries any ``summary``
    passed to :meth:`done`, and keeps a miscounted (over-advancing) stage from
    repeating "100%" on every subsequent tick. If you build a :class:`Stage` by
    hand instead of using ``with``, you must call :meth:`done` yourself.
    """

    def __init__(self, title: str, total: int | None = None) -> None:
        self.title = title
        self.total = int(total) if total is not None else None
        if self.total is not None and self.total < 0:
            self.total = 0
        self.count = 0
        self._stream = _stream()
        self._tty = _is_tty(self._stream)
        self._lock = threading.Lock()
        self._started = time.monotonic()
        self._last_draw = 0.0
        self._width = 0
        # (count, total) as of the last render, or None when nothing has ever been
        # drawn. Compared in done() in place of the rendered text, because the
        # elapsed-time field ticks over between two renders of identical state.
        self._last_state: tuple[int, int | None] | None = None
        self._finished = False
        self._next_non_tty = NON_TTY_STEP
        if self.total == 0:
            # A stage created with an explicit total of zero *has* drawn
            # something, so the "closes having drawn nothing prints nothing"
            # rule in done() does not apply to it. Announcing it is the
            # useful half of the distinction: the caller said there is work
            # here, and telling the operator "0/0, done, nothing to do" is
            # information, whereas a stage that was never told its size and
            # never ran has nothing to report.
            self._render(final=False)

    # -- rendering ---------------------------------------------------------

    def _line(self) -> str:
        elapsed = _fmt_duration(time.monotonic() - self._started)
        if self.total is None:
            return (
                f"[{paint(self.title, 'cyan')}] "
                f"{paint(str(self.count), 'bold')} done  {paint(elapsed, 'dim')}"
            )
        percent = (
            100 if self.count >= self.total else int(self.count * 100 / self.total)
        )
        # Green once finished, yellow while in flight, so a stalled stage is
        # visible at a glance while watching a long run.
        meter = "green" if percent >= 100 else "yellow"
        return (
            f"[{paint(self.title, 'cyan')}] "
            f"{paint(f'{self.count}/{self.total}', 'bold')}  "
            f"{paint(f'{percent:3d}%', meter)}  {paint(elapsed, 'dim')}"
        )

    def _write(self, text: str) -> None:
        _write(self._stream, text)

    def _render(self, final: bool, text: str | None = None) -> None:
        """Draw the bar once. ``final`` terminates the line with a newline.

        On a terminal this is a single ``\\r``-anchored overwrite padded to the
        previous width; it never clears first, because the ``\\r`` plus padding
        already overwrites whatever was there.
        """
        if text is None:
            text = self._line()
        self._last_state = (self.count, self.total)
        if not self._tty:
            self._write(f"{text}\n")
            return
        width = _visible_len(text)
        padding = max(0, self._width - width)
        self._write(f"{_ERASE}{text}{' ' * padding}")
        self._width = width
        if final:
            self._write("\n")

    def _clear_line(self) -> None:
        if self._tty and self._width:
            self._write(f"{_ERASE}{' ' * self._width}{_ERASE}")
            self._width = 0

    # -- public API --------------------------------------------------------

    def advance(self, n: int = 1) -> None:
        """Record ``n`` more finished items and redraw if the throttle allows."""
        if n <= 0 or self._finished:
            return
        with self._lock:
            self.count += n
            if self._tty:
                now = time.monotonic()
                if now - self._last_draw < REDRAW_INTERVAL:
                    return
                self._last_draw = now
                self._render(final=False)
                return
            if self.total is None:
                if self.count % NON_TTY_CHUNK:
                    return
            else:
                percent = (
                    100
                    if self.count >= self.total
                    else int(self.count * 100 / self.total)
                )
                if percent < self._next_non_tty:
                    return
                if percent >= 100:
                    # done() owns the completed line.
                    return
                self._next_non_tty = percent + NON_TTY_STEP
            self._render(final=False)

    def log(self, msg: str) -> None:
        """Emit one notable line, keeping any in-place counter intact."""
        with self._lock:
            self._clear_line()
            self._write(f"{msg}\n")
            if self._tty and not self._finished:
                self._render(final=False)

    def done(self, summary: str = "") -> None:
        """Close the stage, rendering its final line exactly once.

        Safe to call more than once. A stage that did no work and never drew
        anything prints nothing at all, rather than claiming a measurement for
        a stage that never ran -- but a ``summary`` handed to such a stage is
        still emitted, so nothing is silently swallowed. (A stage created with
        ``total=0`` is not in that case: it drew a line when it was built.)
        When the bar already on screen is the completed state -- which is what
        happens after :meth:`log`, and after the last throttled tick -- the
        line is only terminated, not redrawn.
        """
        with self._lock:
            if self._finished:
                return
            self._finished = True
            if self._last_state is None:
                if self.count == 0:
                    if summary:
                        self._write(f"{summary}\n")
                    return
            elif self._last_state == (self.count, self.total):
                if self._tty:
                    self._write("\n")
                if summary:
                    self._write(f"{summary}\n")
                return
            text = self._line()
            if summary:
                text = f"{text}  {summary}"
            self._render(final=True, text=text)

    def __enter__(self) -> Stage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.done()


def stage(title: str, total: int | None = None) -> Stage:
    """Create a :class:`Stage`; prefer using it as a context manager.

    Exactly what an empty stage prints depends on whether it was told its size:

    * ``stage(title, 0)`` renders ``[title] 0/0 100%`` immediately, on
      construction. The caller asserted that this stage exists and has nothing
      to do, and "reached, nothing to do" is worth one line -- an operator
      watching a long run needs to see that a stage was not skipped.
    * ``stage(title)`` or ``stage(title, n)`` with ``n > 0`` draws nothing
      until work actually starts, and a stage closed having drawn nothing and
      having done nothing prints nothing at all: ``[x] 0 done 0.0s`` is a
      measurement of a stage that never ran, and the caller's own summary
      lines already say the work was empty.

    Either way a ``summary`` passed to :meth:`Stage.done` is emitted, so the
    suppression never swallows information the caller handed over.
    """
    return Stage(title, total)


def log(msg: str) -> None:
    """Print one notable line, for events outside any stage.

    A stdout that has gone away costs the line, not the run: this goes through
    the same guarded write as :class:`Stage`, so a closed or broken stream
    cannot abort the caller between stages. (A merely-closed pipe, ``| head``,
    usually fails at the flush rather than the write when stdout is
    block-buffered, which the old half-guard did catch; it is a stdout closed
    out from under us -- which makes *write* raise -- that used to kill the run.)
    """
    _write(_stream(), f"{msg}\n")


def summary_table(rows: Sequence[tuple[str, int]]) -> None:
    """Print aligned ``label  count`` rows for the final report.

    Counts are right-aligned against the widest one so the numbers line up as a
    column, which is the part that actually matters in a report. The label is
    dimmed and the count is bold, applied *after* the padding so the codes
    cannot disturb the alignment. Like :func:`log`, a dead stdout costs the table
    rather than the run.
    """
    items = list(rows)
    if not items:
        return
    label_width = max(len(str(label)) for label, _ in items)
    count_width = max(len(_fmt_count(value)) for _, value in items)
    out = sys.stdout
    for label, value in items:
        name = f"{label!s:<{label_width}}"
        count = f"{_fmt_count(value):>{count_width}}"
        _write(out, f"  {paint(name, 'dim')}  {paint(count, 'bold')}\n")


def _fmt_count(value: object) -> str:
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)
