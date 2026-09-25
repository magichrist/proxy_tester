"""Tests for progress.py -- terminal progress reporting.

The behaviour that matters is what happens when stdout is *not* a terminal,
because that is the case in CI, in a pipe, and in this test suite. The module
must fall back to sparse whole lines; it must never emit a carriage-return
redraw storm, which is what flooded the old logs.
"""

from __future__ import annotations

import io
import sys
import threading
import unittest

try:  # discovery puts tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

import progress


class _Capture:
    """Replaces sys.stdout with a non-TTY StringIO for the duration of a test."""

    def __init__(self) -> None:
        self.buffer = io.StringIO()
        self._original = sys.stdout

    def __enter__(self) -> "_Capture":
        sys.stdout = self.buffer
        return self

    def __exit__(self, *exc: object) -> None:
        sys.stdout = self._original

    @property
    def text(self) -> str:
        return self.buffer.getvalue()

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


class StageAdvanceTests(unittest.TestCase):
    """A Stage must be safe to drive no matter how much is known about the total."""

    def test_advances_with_an_unknown_total(self) -> None:
        with _Capture() as out:
            stage = progress.stage("scanning", None)
            for _ in range(250):
                stage.advance()
            stage.done("finished")
        self.assertEqual(stage.count, 250)
        self.assertIsNone(stage.total)
        self.assertTrue(out.lines, "a stage must emit at least a final line")
        self.assertTrue(any("250" in line for line in out.lines))
        self.assertTrue(any("finished" in line for line in out.lines))

    def test_advances_with_a_known_total(self) -> None:
        with _Capture() as out:
            with progress.stage("scanning", 10) as stage:
                for _ in range(10):
                    stage.advance()
        self.assertEqual(stage.count, 10)
        self.assertIn("10/10", out.text)
        self.assertIn("100%", out.text)

    def test_advance_by_n(self) -> None:
        with _Capture():
            stage = progress.stage("bulk", None)
            stage.advance(5)
            stage.advance(7)
            self.assertEqual(stage.count, 12)

    def test_advance_ignores_non_positive_and_post_done_calls(self) -> None:
        with _Capture():
            stage = progress.stage("bulk", 10)
            stage.advance(0)
            stage.advance(-5)
            self.assertEqual(stage.count, 0)
            stage.done()
            stage.advance(3)
            self.assertEqual(stage.count, 0, "a finished stage must not keep counting")

    def test_zero_total_is_not_a_division_error(self) -> None:
        with _Capture() as out:
            stage = progress.stage("empty", 0)
            stage.done()
        self.assertEqual(stage.count, 0)
        self.assertIn("0/0", out.text)

    def test_negative_total_is_clamped(self) -> None:
        with _Capture():
            stage = progress.stage("weird", -5)
            self.assertEqual(stage.total, 0)
            stage.advance()
            stage.done()

    def test_done_is_idempotent(self) -> None:
        with _Capture() as out:
            stage = progress.stage("once", 5)
            stage.advance(5)
            stage.done("summary")
            first = out.text
            stage.done("summary")
            stage.done("summary")
            self.assertEqual(out.text, first, "done() must not re-render")

    def test_log_emits_its_own_line(self) -> None:
        with _Capture() as out:
            stage = progress.stage("chatty", 10)
            stage.log("a notable event happened")
            stage.done()
        self.assertIn("a notable event happened", out.lines)

    def test_context_manager_closes_the_stage(self) -> None:
        with _Capture() as out:
            with progress.stage("ctx", 4) as stage:
                stage.advance(4)
            self.assertEqual(stage.count, 4)
        self.assertTrue(out.text.endswith("\n"), "a closed stage must end on a newline")


class EmptyStageTests(unittest.TestCase):
    """An empty stage must do exactly what :func:`progress.stage` says it does.

    The docstring used to promise unconditionally that a stage which did no work
    "renders nothing at all", which was true for a stage whose total was unknown
    or non-zero and false for ``total=0``, which announces ``0/0`` the moment it
    is built. The docstring is now the accurate one; these tests pin both halves
    of it, so the next change to either has to be a deliberate one.
    """

    def test_a_zero_total_stage_announces_itself(self) -> None:
        """``stage(title, 0)`` renders immediately: the caller said it exists."""
        with _Capture() as out:
            progress.stage("empty", 0)
        self.assertEqual(len(out.lines), 1)
        self.assertIn("0/0", out.lines[0])
        self.assertIn("empty", out.lines[0])

    def test_a_zero_total_stage_closes_without_a_second_line(self) -> None:
        """done() only terminates the line it already drew; it does not redraw."""
        with _Capture() as out:
            with progress.stage("empty", 0) as stage:
                pass
            self.assertEqual(stage.count, 0)
        self.assertEqual(len(out.lines), 1, "done() re-rendered a stage that had drawn")

    def test_an_unknown_total_stage_that_never_ran_renders_nothing(self) -> None:
        """``stage(title)`` with no work prints nothing, as documented."""
        with _Capture() as out:
            with progress.stage("untouched") as stage:
                pass
            self.assertIsNone(stage.total)
        self.assertEqual(out.text, "")

    def test_a_known_total_stage_that_never_ran_renders_nothing(self) -> None:
        """Same for a non-zero total that was never reached."""
        with _Capture() as out:
            with progress.stage("untouched", 5) as stage:
                pass
            self.assertEqual(stage.count, 0)
        self.assertEqual(out.text, "", "0/5 would be a measurement of a stage that never ran")

    def test_a_summary_is_emitted_even_when_the_stage_prints_nothing(self) -> None:
        """Suppressing the bar must never swallow what the caller handed over.

        The other half of the documented contract: a stage that closes having
        drawn nothing emits no bar, but a ``summary`` is still written, so the
        caller's information is not silently dropped.
        """
        for total in (None, 5, 0):
            with self.subTest(total=total):
                with _Capture() as out:
                    progress.stage("empty", total).done("nothing to do here")
                self.assertIn("nothing to do here", out.text)


class NonTtyTests(unittest.TestCase):
    """Piped/CI output must be sparse lines, not a carriage-return storm."""

    def test_no_carriage_return_is_emitted(self) -> None:
        with _Capture() as out:
            with progress.stage("noisy", 100) as stage:
                for _ in range(100):
                    stage.advance()
        self.assertNotIn("\r", out.text, "a non-TTY must never redraw in place")
        self.assertNotIn("\x1b[2K", out.text, "a non-TTY must never emit an ANSI erase")

    def test_unknown_total_emits_a_bounded_number_of_lines(self) -> None:
        with _Capture() as out:
            with progress.stage("huge", None) as stage:
                for _ in range(1000):
                    stage.advance()
        self.assertLessEqual(
            len(out.lines), 20,
            f"1000 advances produced {len(out.lines)} lines; a pipe should get a handful",
        )

    def test_known_total_emits_far_fewer_lines_than_items(self) -> None:
        with _Capture() as out:
            with progress.stage("huge", 1000) as stage:
                for _ in range(1000):
                    stage.advance()
        self.assertLessEqual(len(out.lines), 12)
        self.assertGreaterEqual(len(out.lines), 1)

    def test_every_emitted_line_is_complete(self) -> None:
        with _Capture() as out:
            with progress.stage("huge", 200) as stage:
                for _ in range(200):
                    stage.advance()
        for line in out.lines:
            self.assertTrue(line.startswith("["), f"truncated in-place redraw: {line!r}")


class _BrokenStream(io.StringIO):
    """A stdout that raises on every write, like a closed pipe."""

    def write(self, _text: str) -> int:
        raise OSError("closed")

    def flush(self) -> None:
        raise OSError("closed")


class SummaryTableTests(unittest.TestCase):
    """summary_table is the final report block."""

    def test_contains_every_row(self) -> None:
        rows = [("links_in", 12345), ("endpoints", 678), ("tls_ok", 9), ("tls_failed", 10)]
        with _Capture() as out:
            progress.summary_table(rows)
        for label, value in rows:
            with self.subTest(label=label):
                self.assertIn(label, out.text)
                self.assertIn(f"{value:,}", out.text)

    def test_rows_are_in_the_order_given(self) -> None:
        rows = [("alpha", 1), ("beta", 2), ("gamma", 3)]
        with _Capture() as out:
            progress.summary_table(rows)
        self.assertEqual(
            [line.split()[0] for line in out.lines], ["alpha", "beta", "gamma"]
        )

    def test_counts_are_right_aligned_into_a_column(self) -> None:
        with _Capture() as out:
            progress.summary_table([("a", 1), ("bbbbbbbbbb", 1234567)])
        numbers = [line.split()[-1] for line in out.lines]
        self.assertEqual(numbers, ["1", "1,234,567"])
        self.assertEqual(len({len(line) for line in out.lines}), 1, "rows must be the same width")

    def test_empty_rows_emits_nothing(self) -> None:
        with _Capture() as out:
            progress.summary_table([])
        self.assertEqual(out.text, "")


class LogTests(unittest.TestCase):
    """progress.log is used by the stages for their handful of notable lines."""

    def test_log_writes_a_single_line(self) -> None:
        with _Capture() as out:
            progress.log("probe: 3/10 links alive")
        self.assertEqual(out.lines, ["probe: 3/10 links alive"])

    def test_a_stage_survives_a_broken_stream(self) -> None:
        """Stage._write swallows OSError, so progress reporting cannot kill a run."""
        original = sys.stdout
        sys.stdout = _BrokenStream()
        try:
            with progress.stage("broken", 10) as stage:
                stage.advance(10)
                stage.log("a notable event")
            self.assertEqual(stage.count, 10)
        finally:
            sys.stdout = original

    def test_log_survives_a_broken_stream(self) -> None:
        """progress.log must not propagate a dead stdout to its caller.

        Regression: log() guarded flush() but not write(), unlike Stage._write,
        so a closed or broken stdout raised OSError out of log() and aborted the
        caller mid-run. The stages call log() for their summary lines, so this is
        on the happy path of a run whose stdout went away -- ``| head``, or a CI
        job whose reader exited. Both log() and the module-level summary_table
        now go through the same guarded write Stage uses.
        """
        original = sys.stdout
        sys.stdout = _BrokenStream()
        try:
            progress.log("ignored")
            progress.summary_table([("links_in", 3)])
        finally:
            sys.stdout = original

    def test_log_survives_a_closed_stdout(self) -> None:
        """The real thing, not a mock: a genuinely closed file object.

        ``_BrokenStream`` raises on every call, which is what a broken pipe looks
        like. A stream that has actually been *closed* raises ``ValueError`` from
        write() instead, so the guard has to cover that too -- and it is the
        failure a long run hits when its own stdout is closed out from under it.
        """
        original = sys.stdout
        stream = io.StringIO()
        stream.close()
        sys.stdout = stream
        try:
            progress.log("ignored")
        finally:
            sys.stdout = original

    def test_a_full_run_of_log_calls_completes_on_a_broken_stream(self) -> None:
        """Losing the lines must not lose the run.

        The shape of the real bug: the caller is mid-pipeline, logging between
        stages, when the pipe dies. Every remaining log() call has to be a no-op
        rather than the one that raises.
        """
        original = sys.stdout
        sys.stdout = _BrokenStream()
        reached_end = False
        try:
            for i in range(200):
                progress.log(f"stage {i} done")
            reached_end = True
        finally:
            sys.stdout = original
        self.assertTrue(reached_end, "log() aborted the caller on a broken stream")


class ThreadSafetyTests(unittest.TestCase):
    """Stages are advanced from worker threads; the counter must stay exact."""

    def test_concurrent_advance_does_not_lose_counts(self) -> None:
        with _Capture():
            stage = progress.stage("threads", 800)

            def worker() -> None:
                for _ in range(100):
                    stage.advance()

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(stage.count, 800)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
