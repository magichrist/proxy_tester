"""Tests for base64_decryptor.py -- subscription payload decoding.

Subscription endpoints serve their whole link list base64-encoded, and just as
often wrapped at 64 or 76 characters. The pre-refactor decoder only fired when
a *single line* matched ``[A-Za-z0-9+/=]+``, so a wrapped payload was copied
through verbatim and the run silently produced an identical file.
"""

from __future__ import annotations

import base64
import textwrap
import unittest

try:  # discovery puts tests/ on tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

import base64_decryptor


def _wrap_keeping_a_long_tail(blob: str, width: int) -> list[str]:
    """Wrap ``blob`` at ``width``, trimming the width until the tail is >= 4 chars.

    A trailing fragment shorter than four characters hits a separate defect that
    :class:`WrappedPayloadTests` pins separately; this helper keeps the other
    tests focused on one thing each.
    """
    for candidate in range(width, width + 8):
        wrapped = textwrap.wrap(blob, candidate)
        if len(wrapped) > 1 and len(wrapped[-1]) >= 4:
            return wrapped
    return textwrap.wrap(blob, width)


LINKS = [
    "vless://11111111-1111-1111-1111-111111111111@edge1.proxy.example:443?type=ws#one",
    "trojan://secret@edge2.proxy.example:8443?sni=cdn.proxy.example#two",
    "vmess://22222222-2222-2222-2222-222222222222@edge3.proxy.example:443#three",
]
PAYLOAD = "\n".join(LINKS) + "\n"


class PassthroughTests(support.LoopbackTestCase):
    """A file that is already plain text must come out byte-identical."""

    def test_plain_text_passes_through_untouched(self) -> None:
        source = support.write_lines(self.path("in.txt"), LINKS)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)
        self.assertFalse(stats.decoded, "a plain link file is not a decode")
        self.assertEqual(stats.decoded_blocks, 0)
        self.assertEqual(stats.lines_in, len(LINKS))
        self.assertEqual(stats.lines_out, len(LINKS))

    def test_prose_and_junk_are_not_mangled(self) -> None:
        lines = [
            "not base64 at all, just a sentence with spaces",
            "404 Not Found",
            "<html><body>nope</body></html>",
            "vless://u@edge1.proxy.example:443#real",
        ]
        source = support.write_lines(self.path("in.txt"), lines)
        base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), lines)

    def test_crlf_input_is_normalised_to_lf(self) -> None:
        source = support.write_lines(self.path("in.txt"), LINKS, newline="\r\n")
        base64_decryptor.runner(source, self.path("out.txt"))
        with open(self.path("out.txt"), "rb") as handle:
            self.assertNotIn(b"\r", handle.read())


class SingleLinePayloadTests(support.LoopbackTestCase):
    """The easy case: one line holding the whole payload."""

    def test_single_line_base64_is_decoded(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        source = support.write_lines(self.path("in.txt"), [blob])
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)
        self.assertTrue(stats.decoded)
        self.assertEqual(stats.decoded_blocks, 1)
        self.assertEqual(stats.decoded_lines, len(LINKS))

    def test_urlsafe_alphabet_is_decoded(self) -> None:
        """The URL-safe alphabet is decoded exactly like the standard one.

        Regression: the guards used to gate on the standard ``_B64_CHARS`` set
        while ``_decode_body`` translated ``-_`` to ``+/`` and documented that it
        took both alphabets, so a payload containing ``-`` or ``_`` was refused
        by the gate and copied through verbatim. The guard now accepts both
        alphabets, so guard and decoder agree.
        """
        blob = base64.urlsafe_b64encode(PAYLOAD.encode()).decode().rstrip("=")
        self.assertIn(
            "-_", blob + "-_", "the fixture must exercise the URL-safe alphabet"
        )
        source = support.write_lines(self.path("in.txt"), [blob])
        base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)

    def test_urlsafe_payload_is_accepted_by_the_guards(self) -> None:
        """is_base64 and the run scanner must agree with the decoder.

        A guard that refuses what the decoder can read turns a subscription into
        a file of base64 gibberish; a guard that accepts too much mangles a plain
        link file. The URL-safe alphabet used to fall on the wrong side of that.
        """
        blob = base64.urlsafe_b64encode(PAYLOAD.encode()).decode().rstrip("=")
        self.assertTrue(base64_decryptor.is_base64(blob))
        self.assertTrue(
            base64_decryptor.is_base64("\n".join(_wrap_keeping_a_long_tail(blob, 64))),
            "a URL-safe payload wrapped across lines must still pass the guard",
        )
        self.assertTrue(base64_decryptor._looks_like_base64(blob))

    def test_a_wrapped_urlsafe_payload_is_decoded(self) -> None:
        """URL-safe plus wrapped, which is what a real feed looks like."""
        blob = base64.urlsafe_b64encode(PAYLOAD.encode()).decode().rstrip("=")
        source = support.write_lines(
            self.path("in.txt"), _wrap_keeping_a_long_tail(blob, 64)
        )
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)
        self.assertEqual(stats.decoded_blocks, 1)

    def test_missing_padding_is_tolerated(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode().rstrip("=")
        source = support.write_lines(self.path("in.txt"), [blob])
        base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)


class WrappedPayloadTests(support.LoopbackTestCase):
    """The regression: a payload broken across several lines must still decode."""

    def test_wrapped_at_76_columns_is_decoded(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        wrapped = textwrap.wrap(blob, 76)
        self.assertGreater(len(wrapped), 1, "the payload must actually wrap")
        source = support.write_lines(self.path("in.txt"), wrapped)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)
        self.assertTrue(stats.decoded)
        self.assertEqual(stats.lines_in, len(wrapped))
        self.assertEqual(stats.lines_out, len(LINKS))

    def test_wrapped_at_64_columns_is_decoded(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        wrapped = _wrap_keeping_a_long_tail(blob, 64)
        self.assertGreater(len(wrapped), 1)
        source = support.write_lines(self.path("in.txt"), wrapped)
        base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)

    def test_wrapped_at_a_width_that_leaves_a_long_enough_tail_is_decoded(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        checked = 0
        for width in range(4, 120):
            wrapped = textwrap.wrap(blob, width)
            if len(wrapped) < 2 or len(wrapped[-1]) < 4:
                continue
            with self.subTest(width=width):
                source = support.write_lines(self.path("in.txt"), wrapped)
                base64_decryptor.runner(source, self.path("out.txt"))
                self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)
                checked += 1
        self.assertGreater(checked, 10, "the sweep must actually exercise some widths")

    def test_a_final_fragment_of_one_to_three_chars_is_still_joined(self) -> None:
        """A wrapped run whose last line is 1-3 chars must decode completely.

        Regression: a run was only extended while the line held at least
        ``MIN_LINE_LEN`` (4) characters, so a 1-3 character tail -- usually the
        tail of the ``=`` padding -- was emitted into the output as a bogus
        extra line. The per-line length floor is gone; the run scanner admits
        any non-empty line drawn from the alphabet and the joined run is what
        has to decode.
        """
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        short_tails = [
            width
            for width in range(4, 120)
            if len(textwrap.wrap(blob, width)) > 1
            and 1 <= len(textwrap.wrap(blob, width)[-1]) <= 3
        ]
        self.assertTrue(short_tails, "the fixture must produce a short tail somewhere")
        for width in short_tails:
            with self.subTest(width=width):
                source = support.write_lines(
                    self.path("in.txt"), textwrap.wrap(blob, width)
                )
                base64_decryptor.runner(source, self.path("out.txt"))
                self.assertEqual(support.read_lines(self.path("out.txt")), LINKS)

    def test_a_short_tail_never_reaches_the_output(self) -> None:
        """The tail is joined into the payload, not leaked as its own line.

        The precise failure the length floor caused: the decoded text gained a
        line that was never in the payload, so the pipeline parsed a link that
        does not exist and reported a link count one too high.
        """
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        checked = 0
        for width in range(4, 120):
            wrapped = textwrap.wrap(blob, width)
            if len(wrapped) < 2 or len(wrapped[-1]) > 3:
                continue
            with self.subTest(width=width, tail=wrapped[-1]):
                source = support.write_lines(self.path("in.txt"), wrapped)
                base64_decryptor.runner(source, self.path("out.txt"))
                out = support.read_lines(self.path("out.txt"))
                self.assertEqual(out, LINKS, f"width={width} leaked a tail line")
                self.assertNotIn(wrapped[-1], out)
            checked += 1
        self.assertGreater(checked, 3, "the sweep must actually hit short tails")

    def test_a_padding_only_tail_is_handled(self) -> None:
        """Both kinds of ``=`` tail: the genuine one joins, the stray one stands.

        A payload whose own padding is split off onto its own line -- the real
        bug -- must be joined, so no ``=`` line reaches the output. A ``=`` that
        was never part of the payload is not ours to swallow: this module passes
        every non-payload line through untouched, which is also what keeps
        ``start.py``'s conservation accounting honest. What matters in both
        cases is that the payload in front of the tail still decodes.
        """
        payload = base64.b64encode(PAYLOAD.encode()).decode()
        for label, lines, expected in [
            (
                "payload wrapped to end on =",
                textwrap.wrap(payload[:-1], 64) + ["="],
                LINKS,
            ),
            (
                "payload wrapped to end on ==",
                textwrap.wrap(payload[:-2], 64) + ["=="],
                LINKS,
            ),
            (
                "payload then stray =",
                _wrap_keeping_a_long_tail(payload, 64) + ["="],
                LINKS + ["="],
            ),
            (
                "payload then stray ==",
                _wrap_keeping_a_long_tail(payload, 64) + ["=="],
                LINKS + ["=="],
            ),
        ]:
            with self.subTest(label=label):
                source = support.write_lines(self.path("in.txt"), lines)
                stats = base64_decryptor.runner(source, self.path("out.txt"))
                out = support.read_lines(self.path("out.txt"))
                self.assertEqual(out, expected, f"{label} mishandled the tail")
                self.assertEqual(stats.decoded_blocks, 1, f"{label} lost the payload")
                self.assertEqual(
                    stats.decoded_lines, len(LINKS), f"{label} leaked into the text"
                )

    def test_a_bare_equals_after_a_payload_does_not_poison_it(self) -> None:
        """The stray-padding case, pinned exactly: the payload survives intact."""
        payload = base64.b64encode(PAYLOAD.encode()).decode()
        source = support.write_lines(
            self.path("in.txt"), _wrap_keeping_a_long_tail(payload, 64) + ["="]
        )
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), LINKS + ["="])
        self.assertEqual(stats.decoded_blocks, 1)
        self.assertEqual(stats.decoded_lines, len(LINKS))

    def test_a_mixed_file_decodes_only_the_base64_run(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        wrapped = _wrap_keeping_a_long_tail(blob, 64)
        before = "vless://plain@edge9.proxy.example:443#before"
        after = "trojan://tail@edge8.proxy.example:443#after"
        source = support.write_lines(self.path("in.txt"), [before] + wrapped + [after])
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(
            support.read_lines(self.path("out.txt")), [before] + LINKS + [after]
        )
        self.assertEqual(stats.decoded_blocks, 1)

    def test_two_separate_base64_runs_both_decode(self) -> None:
        first = base64.b64encode((LINKS[0] + "\n").encode()).decode()
        second = base64.b64encode(("\n".join(LINKS[1:]) + "\n").encode()).decode()
        divider = "vless://divider@edge7.proxy.example:443#divider"
        lines = (
            _wrap_keeping_a_long_tail(first, 40)
            + [divider]
            + _wrap_keeping_a_long_tail(second, 40)
        )
        source = support.write_lines(self.path("in.txt"), lines)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(
            support.read_lines(self.path("out.txt")),
            [LINKS[0], divider] + LINKS[1:],
        )
        self.assertEqual(stats.decoded_blocks, 2)

    def test_a_prose_line_next_to_a_base64_run_does_not_swallow_it(self) -> None:
        """An ordinary sentence after a base64 block must not break the decode.

        Regression: ``_looks_like_base64`` stripped *all* whitespace and then
        asked only whether the remaining characters were in the base64
        alphabet. A plain-English line ("plain trailing line") qualifies, so it
        was glued onto the end of the preceding run, the joined body stopped
        decoding, and the entire base64 block was emitted verbatim. The real
        pipeline then saw a file of base64 gibberish where links should be and
        reported zero parsed links -- silent, total data loss. The run is now
        decoded longest-first and trimmed until it decodes, so the sentence is
        excluded and passed through on its own.
        """
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        lines = _wrap_keeping_a_long_tail(blob, 64) + ["plain trailing line"]
        source = support.write_lines(self.path("in.txt"), lines)
        base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(
            support.read_lines(self.path("out.txt")), LINKS + ["plain trailing line"]
        )

    def test_two_base64_runs_separated_by_prose_both_decode(self) -> None:
        """The same defect, seen as a missed decode rather than a corrupt one."""
        first = base64.b64encode((LINKS[0] + "\n").encode()).decode()
        second = base64.b64encode(("\n".join(LINKS[1:]) + "\n").encode()).decode()
        lines = (
            _wrap_keeping_a_long_tail(first, 40)
            + ["a plain line between them"]
            + _wrap_keeping_a_long_tail(second, 40)
        )
        source = support.write_lines(self.path("in.txt"), lines)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(
            support.read_lines(self.path("out.txt")),
            [LINKS[0], "a plain line between them"] + LINKS[1:],
        )
        self.assertEqual(stats.decoded_blocks, 2)

    def test_prose_around_a_payload_leaves_the_payload_decoded(self) -> None:
        """Prose before, after, and between: every block must still decode.

        This is the whole failure mode in one fixture. The old scanner glued
        any of these into the run, so a single sentence could cost the file
        every link it had.
        """
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        wrapped = _wrap_keeping_a_long_tail(blob, 64)
        lines = (
            ["a note before the payload"]
            + wrapped
            + ["and a comment after it"]
            + _wrap_keeping_a_long_tail(
                base64.b64encode((LINKS[0] + "\n").encode()).decode(), 40
            )
            + ["trailing remark"]
        )
        source = support.write_lines(self.path("in.txt"), lines)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(
            support.read_lines(self.path("out.txt")),
            ["a note before the payload"]
            + LINKS
            + ["and a comment after it", LINKS[0], "trailing remark"],
        )
        self.assertEqual(stats.decoded_blocks, 2)

    def test_a_payload_followed_only_by_prose_still_reports_its_links(self) -> None:
        """The stat a caller reads must survive a prose tail.

        ``decoded_lines`` is what ``start.py`` reports as the number of links
        out, so a prose tail that turned a decode into a passthrough would show
        up as "0 links" rather than as a visible block of base64.
        """
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        lines = _wrap_keeping_a_long_tail(blob, 76) + ["plain trailing line"]
        source = support.write_lines(self.path("in.txt"), lines)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertTrue(
            stats.decoded, "a prose tail must not turn a decode into a passthrough"
        )
        self.assertEqual(stats.decoded_lines, len(LINKS))
        self.assertEqual(stats.lines_out, len(LINKS) + 1)

    def test_a_whole_prose_file_is_still_passed_through_intact(self) -> None:
        """The cost of the permissive candidate test: nothing may be mangled.

        Prose made only of base64 letters is admitted as a candidate and then
        fails to decode, so it is re-examined line by line and emitted
        verbatim. A file of such lines must come out byte-identical.
        """
        lines = [
            "plain trailing line",
            "another sentence of only letters",
            "404NotFound",
            "a third line right here",
            "0123456789",
        ]
        source = support.write_lines(self.path("in.txt"), lines)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(support.read_lines(self.path("out.txt")), lines)
        self.assertFalse(stats.decoded, "prose is not a payload")
        self.assertEqual(stats.decoded_blocks, 0)

    def test_a_blank_line_after_a_payload_does_not_poison_it(self) -> None:
        """A trailing blank-ish line is the same class of damage as prose."""
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        for tail in ([""], ["   "], ["\t"]):
            with self.subTest(tail=tail):
                source = support.write_lines(
                    self.path("in.txt"), _wrap_keeping_a_long_tail(blob, 64) + tail
                )
                stats = base64_decryptor.runner(source, self.path("out.txt"))
                out = support.read_lines(self.path("out.txt"))
                self.assertEqual([line for line in out if line.strip()], LINKS)
                self.assertEqual(stats.decoded_lines, len(LINKS))
                self.assertEqual(len(out), len(LINKS) + len(tail))


class IsBase64Tests(unittest.TestCase):
    """is_base64 is a cheap guard; it must not cry wolf on link lines."""

    def test_accepts_a_payload(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        self.assertTrue(base64_decryptor.is_base64(blob))
        self.assertTrue(
            base64_decryptor.is_base64("\n".join(_wrap_keeping_a_long_tail(blob, 64)))
        )

    def test_rejects_link_lines(self) -> None:
        for line in LINKS:
            with self.subTest(line=line[:24]):
                self.assertFalse(base64_decryptor.is_base64(line))

    def test_rejects_prose_and_short_input(self) -> None:
        for value in (
            "",
            "   ",
            "hello",
            "hello there friend",
            "404 Not Found",
            "a" * 7,
        ):
            with self.subTest(value=value):
                self.assertFalse(base64_decryptor.is_base64(value))

    def test_rejects_non_strings(self) -> None:
        for value in (None, 42, b"payload", ["a"]):  # type: ignore[list-item]
            with self.subTest(value=repr(value)):
                self.assertFalse(base64_decryptor.is_base64(value))  # type: ignore[arg-type]

    def test_rejects_a_digit_run_that_decodes_to_binary(self) -> None:
        """A long numeric string is valid base64 but not a link list."""
        self.assertFalse(base64_decryptor.is_base64("1234567890" * 8))
        self.assertFalse(base64_decryptor.is_base64("9" * 400))

    def test_rejects_binary_noise(self) -> None:
        blob = base64.b64encode(bytes(range(256))).decode()
        self.assertFalse(
            base64_decryptor.is_base64(blob),
            "binary that decodes to control characters is not a link list",
        )

    def test_a_large_non_payload_span_does_not_rescan_quadratically(self) -> None:
        """A big base64-looking file that is not a payload must stay linear.

        Run detection is per line, and each run is retried with the last line
        trimmed off. Done naively -- re-deriving the span end and re-running the
        whole trim loop after every single emitted line -- that is quadratic, and
        a multi-megabyte file of base64-looking text (an embedded certificate, a
        base64 image) takes minutes. The trim budget belongs to the span, not to
        the line, so the number of decode attempts is bounded by the budget
        however long the span is. Asserting the attempt count rather than a
        wall-clock time keeps this deterministic.

        The noise is generated by an inline LCG rather than ``random`` so the
        fixture is byte-for-byte reproducible and needs no import.
        """
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        state, noise = 987654321, []
        for _ in range(40_000):
            state = (1103515245 * state + 12345) % (1 << 31)
            noise.append(alphabet[state % len(alphabet)])
        lines = textwrap.wrap("".join(noise), 76)
        self.assertGreater(len(lines), 500, "the fixture must be a long span")

        real = base64_decryptor._decode_body
        attempts = []

        def counting(body: str) -> str | None:
            attempts.append(len(body))
            return real(body)

        base64_decryptor._decode_body = counting
        self.addCleanup(setattr, base64_decryptor, "_decode_body", real)
        out, blocks, decoded, _ = base64_decryptor._decode_lines(lines)

        self.assertEqual(decoded, 0, "random base64 is not a link list")
        self.assertEqual(out, lines, "a non-payload span must pass through intact")
        self.assertEqual(blocks, 1, "one maximal span, not one per line")
        self.assertLessEqual(
            len(attempts),
            base64_decryptor.MAX_TRIM_LINES + 1,
            f"{len(attempts)} decode attempts for {len(lines)} lines: the span is "
            f"being rescanned per line, which is quadratic",
        )


class StatsTests(support.LoopbackTestCase):
    """runner() reports what it did so the caller need not guess."""

    def test_reports_a_passthrough(self) -> None:
        source = support.write_lines(self.path("in.txt"), LINKS)
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertIsInstance(stats, base64_decryptor.DecodeStats)
        self.assertEqual(stats.b64_blocks, 0)
        self.assertEqual(stats.decoded_blocks, 0)
        self.assertEqual(stats.passthrough_lines, len(LINKS))

    def test_reports_a_decode(self) -> None:
        blob = base64.b64encode(PAYLOAD.encode()).decode()
        source = support.write_lines(
            self.path("in.txt"), _wrap_keeping_a_long_tail(blob, 64)
        )
        stats = base64_decryptor.runner(source, self.path("out.txt"))
        self.assertEqual(stats.decoded_blocks, 1)
        self.assertEqual(stats.decoded_lines, len(LINKS))
        self.assertEqual(stats.b64_blocks, 1)
        self.assertFalse(
            stats.lines_in == stats.lines_out,
            "wrapping must collapse the block into separate lines",
        )

    def test_missing_input_file_raises(self) -> None:
        with self.assertRaises(OSError):
            base64_decryptor.runner(self.path("absent.txt"), self.path("out.txt"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
