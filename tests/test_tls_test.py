"""Tests for tls_test.py -- the TLS handshake stage.

The headline test here is :class:`TlsCheckShapeTests`, which pins the return
shape of :func:`tls_test.tls_check`. The pre-refactor code returned a bare
``False`` on failure and its caller did ``tls_test[1]``, which raises
``TypeError: 'bool' object is not subscriptable``. Indexing element 1 without
first checking element 0 must therefore be impossible, and the test says so.

Three live bugs in this stage are pinned by regression tests:

1. A bare link containing a tab must survive intact (:class:`SplitLineTests`).
   ``_split_line`` used to split on the first tab unconditionally, destroying
   the link and filing its fragment tail as a ``parse`` failure.
2. ``<ms>\\t<link>`` must round-trip its ``planned_ms``
   (:class:`TlsScoredInputTests`). ``_as_ms`` only ever accepted the ``_ms``
   spelling, which :func:`tls_test._render` never writes, so every planned
   timing was discarded.
3. ``Config.apply_overrides`` must actually reach the stage
   (:class:`ConfigOverrideTests`). ``timeout``/``max_workers`` were bound as
   argument defaults, which are evaluated once at definition time, so the CLI's
   ``--set`` had no effect.

Every listener is a loopback TLS server using the throwaway self-signed
certificate embedded in :mod:`support`.
"""

from __future__ import annotations

import io
import os
import socket
import ssl
import unittest
from typing import cast

try:  # discovery puts tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

import Config
import tls_test

#: Slugs the module is allowed to emit in ``(ok, ms, error)``. Taken from the
#: module's own declared set so a newly emitted slug cannot pass undeclared.
VALID_SLUGS = tls_test.ERROR_SLUGS

#: The base vocabulary the refactor spec documents, plus the two extensions this
#: module declares and explains in its docstring. Pinned literally by
#: :meth:`SlugVocabularyTests.test_documented_slug_set_is_exact`.
BASE_SLUGS = frozenset({"timeout", "refused", "dns", "unreachable", "tls", "other"})
EXTENSION_SLUGS = frozenset({"cert", "parse"})


def _link(port: int, tag: str, **query: str) -> str:
    params = "&".join(f"{k}={v}" for k, v in query.items())
    suffix = f"?{params}" if params else ""
    return f"vless://uuid-{tag}@127.0.0.1:{port}{suffix}#note-{tag}"


#: A link whose FRAGMENT contains a tab, on a host that parses. This is the shape
#: that the first-tab split used to destroy.
A_TAB_LINK = "vless://u@127.0.0.1:9002?a=1#tab\there"
#: The same link on ``h``, which is not a valid host, so it is a ``parse``
#: failure. Named as a constant so the exact bug-report string stays quotable.
UNPARSEABLE_TAB_LINK = "vless://u@h:9002?a=1#tab\there"


class _CertFiles:
    """Lazily materialises the embedded self-signed cert as two temp files."""

    def __init__(self, workdir: str) -> None:
        self.certfile = os.path.join(workdir, "server-cert.pem")
        self.keyfile = os.path.join(workdir, "server-key.pem")
        with open(self.certfile, "w", encoding="ascii") as handle:
            handle.write(support.SELF_SIGNED_CERT)
        with open(self.keyfile, "w", encoding="ascii") as handle:
            handle.write(support.SELF_SIGNED_KEY)


class TlsCheckShapeTests(support.LoopbackTestCase):
    """REGRESSION: tls_check must always return a 3-tuple."""

    def test_failure_returns_a_three_tuple(self) -> None:
        result = tls_test.tls_check(
            "127.0.0.1", support.closed_port(), "localhost", 1.0
        )
        self.assertIsInstance(result, tuple, "the old code returned a bare bool here")
        self.assertEqual(len(result), 3)
        self.assertEqual(result, (False, None, "refused"))

    def test_empty_host_returns_dns(self) -> None:
        self.assertEqual(tls_test.tls_check("", 443, None, 1.0), (False, None, "dns"))

    def test_index_one_before_index_zero_never_raises(self) -> None:
        """The exact expression the old code used, on a failing handshake."""
        result = tls_test.tls_check(
            "127.0.0.1", support.closed_port(), "localhost", 1.0
        )
        self.assertFalse(result[0])
        self.assertIsNone(result[1], "index 1 must be safe to read on the failure path")
        self.assertIsInstance(result[2], str)

    def test_unpacking_works_on_every_failure_path(self) -> None:
        dead = support.closed_port()
        for host, port, sni in (
            ("", 443, None),
            ("127.0.0.1", dead, "localhost"),
            ("127.0.0.1", dead, None),
        ):
            with self.subTest(host=host, port=port, sni=sni):
                ok, ms, error = tls_test.tls_check(host, port, sni, 0.5)
                self.assertIs(ok, False)
                self.assertIsNone(ms)
                self.assertIn(error, VALID_SLUGS)

    def test_never_raises_on_junk_arguments(self) -> None:
        for host, port, timeout in (
            ("127.0.0.1", -1, 0.1),
            ("127.0.0.1", 0, 0.1),
            ("127.0.0.1", 70000, 0.1),
            ("127.0.0.1", 1, 0.0),
        ):
            with self.subTest(port=port, timeout=timeout):
                result = tls_test.tls_check(host, port, None, timeout)
                self.assertIsInstance(result, tuple)
                self.assertEqual(len(result), 3)


class TlsVerificationTests(support.LoopbackTestCase):
    """A local self-signed server: rejected by default, accepted with insecure."""

    def setUp(self) -> None:
        super().setUp()
        self.certs = _CertFiles(self.workdir)

    def test_self_signed_fails_default_verification(self) -> None:
        with support.tls_listener(self.certs.certfile, self.certs.keyfile) as server:
            ok, ms, error = tls_test.tls_check(
                "127.0.0.1", server.port, "localhost", 3.0
            )
        self.assertIs(ok, False, "a self-signed certificate must not verify by default")
        self.assertIsNone(ms)
        self.assertEqual(error, "cert")

    def test_self_signed_succeeds_with_insecure(self) -> None:
        with support.tls_listener(self.certs.certfile, self.certs.keyfile) as server:
            ok, ms, error = tls_test.tls_check(
                "127.0.0.1", server.port, "localhost", 3.0, insecure=True
            )
        self.assertIs(ok, True)
        self.assertIsNone(error)
        assert isinstance(ms, float)
        self.assertGreaterEqual(ms, 0.0)

    def test_insecure_is_read_from_the_link_query(self) -> None:
        private = "_insecure_requested"
        cases = [
            (_link(1, "a", allowInsecure="1"), True),
            (_link(1, "b", insecure="true"), True),
            (_link(1, "c", insecure="0"), False),
            (_link(1, "d", allowInsecure="1", insecure="0"), False),
            (_link(1, "e"), False),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertIs(getattr(tls_test, private)(text), expected)


class TlsRunnerConservationTests(support.LoopbackTestCase):
    """Requirement 3: for an input of N lines, ok + failed == N. Nothing dropped."""

    def test_link_conservation_over_mixed_input(self) -> None:
        dead = support.closed_port()
        lines = [
            _link(dead, "fail1"),
            "this is not a link",
            "<html><body>404</body></html>",
            "proxy.example:notaport",
            _link(dead, "fail2"),
            "",
            "   ",
            "vless://",
            _link(dead, "fail3"),
        ]
        path = support.write_lines(self.path("in.txt"), lines)
        with self.quiet():
            stats = tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=4,
            )
        ok_rows = support.read_lines(self.path("out.tls"))
        bad_rows = support.read_lines(self.path("out.tls_faulty"))
        self.assertEqual(
            stats["tested"], len(lines) - 2, "blank lines are skipped, not tested"
        )
        self.assertEqual(len(ok_rows) + len(bad_rows), stats["tested"])
        self.assertEqual(stats["ok"], len(ok_rows))
        self.assertEqual(stats["failed"], len(bad_rows))
        self.assertEqual(stats["ok"] + stats["failed"], stats["tested"])

    def test_unparseable_lines_are_recorded_as_failures(self) -> None:
        lines = ["not a link", "<html>error</html>", "proxy.example:notaport"]
        path = support.write_lines(self.path("in.txt"), lines)
        with self.quiet():
            stats = tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=2,
            )
        bad = support.read_lines(self.path("out.tls_faulty"))
        self.assertEqual(stats["failed"], 3)
        self.assertEqual(len(bad), 3)
        for row in bad:
            self.assertEqual(row.split("\t", 1)[0], "parse")
        # The original junk text is preserved, not normalised away.
        for original in lines:
            self.assertIn(original, [row.split("\t", 1)[1] for row in bad])

    def test_every_failure_carries_a_reason_field(self) -> None:
        dead = support.closed_port()
        path = support.write_lines(
            self.path("in.txt"), [_link(dead, "a"), "junk", _link(dead, "b")]
        )
        with self.quiet():
            tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=2,
            )
        for row in support.read_lines(self.path("out.tls_faulty")):
            field = row.split("\t", 1)[0]
            self.assertTrue(field, "a faulty row must say why")
            self.assertIn(field, VALID_SLUGS)


class TlsRunnerOutputTests(support.LoopbackTestCase):
    """Ordering, byte-for-byte preservation and the faulty_file=None contract."""

    def _run_with_stubbed_handshakes(self, latencies: list[float], lines: list[str]):
        """Drive tls_runner_threaded with deterministic handshake timings."""
        queue = list(latencies)

        def fake_tls_check(host, port, sni, timeout, *, insecure=False):  # type: ignore[no-untyped-def]
            ms = queue.pop(0) if queue else 1.0
            return (True, ms, None)

        original = tls_test.tls_check
        tls_test.tls_check = fake_tls_check
        self.addCleanup(setattr, tls_test, "tls_check", original)

        path = support.write_lines(self.path("in.txt"), lines)
        with self.quiet():
            stats = tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=1.0,
                max_workers=4,
            )
        return stats

    def test_output_is_numerically_sorted_ascending(self) -> None:
        latencies = [100.0, 9.0, 10.0, 2.0]
        lines = [_link(1000 + i, f"n{i}") for i in range(4)]
        self._run_with_stubbed_handshakes(latencies, lines)
        rows = support.read_scored(self.path("out.tls"))
        values = [ms for ms, _link_text in rows]
        self.assertEqual(values, [2.0, 9.0, 10.0, 100.0])
        self.assertEqual(values, sorted(values))
        self.assertNotEqual(
            values,
            sorted(values, key=str),
            "the ordering must be numeric, not lexicographic",
        )

    def test_integer_milliseconds_render_without_a_decimal(self) -> None:
        self._run_with_stubbed_handshakes(
            [5.0, 7.0], [_link(2001, "a"), _link(2002, "b")]
        )
        for row in support.read_lines(self.path("out.tls")):
            field = row.split("\t", 1)[0]
            self.assertNotIn(".", field, f"{field!r} should render as a whole number")

    #: Links whose text is awkward: spaces, an embedded tab, unicode, a '#'
    #: inside a JSON query value, a second '#', percent-encoding, quotes.
    AWKWARD = [
        "vless://u@127.0.0.1:9001?a=1#note with spaces",
        "vless://u@127.0.0.1:9002?a=1#tab\there",
        "vless://u@127.0.0.1:9003?a=1#\u044e\u043d\u0438\u043a\u043e\u0434 \u2713 \u65e5\u672c\u8a9e",
        'vless://u@127.0.0.1:9004?json={"a":"b#c"}#frag#ment',
        "trojan://p%40w@127.0.0.1:9005?sni=cdn.example#'quoted'",
    ]

    def test_scored_input_preserves_link_text_byte_for_byte(self) -> None:
        """With a '<ms>\\t<link>' prefix, only the first tab may be consumed."""
        lines = [f"{100 + index}.0\t{text}" for index, text in enumerate(self.AWKWARD)]
        self._run_with_stubbed_handshakes([1.0] * len(lines), lines)
        written = [
            row.split("\t", 1)[1] for row in support.read_lines(self.path("out.tls"))
        ]
        self.assertEqual(sorted(written), sorted(self.AWKWARD))

    def test_bare_input_with_a_tab_is_preserved_byte_for_byte(self) -> None:
        """REGRESSION (bug 1): a tab is not a separator unless the field is a score.

        ``tls_test._split_line`` used to split on the *first* tab unconditionally,
        so a bare link whose fragment contains a tab had its head swallowed and
        only the tail survived. The pipeline feeds the TLS stage bare links, so
        this corrupted and then lost a real link. ``_split_line`` now strips a
        leading field only when it matches a score or a known reason slug.
        """
        self._run_with_stubbed_handshakes([1.0] * len(self.AWKWARD), list(self.AWKWARD))
        written = [
            row.split("\t", 1)[1] for row in support.read_lines(self.path("out.tls"))
        ]
        self.assertEqual(sorted(written), sorted(self.AWKWARD))

    def test_faulty_file_none_writes_nothing_and_still_counts(self) -> None:
        dead = support.closed_port()
        path = support.write_lines(self.path("in.txt"), [_link(dead, "a"), "junk"])
        out = self.path("out.tls")
        with self.quiet():
            stats = tls_test.tls_runner_threaded(
                path, out, None, timeout=0.5, max_workers=2
            )
        self.assertEqual(stats, {"tested": 2, "ok": 0, "failed": 2})
        self.assertTrue(os.path.exists(out), "the success artifact is still written")
        self.assertEqual(
            [p for p in os.listdir(self.workdir) if "faulty" in p],
            [],
            "no faulty file may be created when faulty_file is None",
        )

    def test_blank_lines_are_skipped_and_not_counted(self) -> None:
        path = support.write_lines(
            self.path("in.txt"), ["", "   ", _link(support.closed_port(), "a"), ""]
        )
        with self.quiet():
            stats = tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=2,
            )
        self.assertEqual(stats["tested"], 1)

    def test_missing_input_file_raises(self) -> None:
        with self.assertRaises(OSError):
            tls_test.tls_runner_threaded(
                self.path("absent.txt"), self.path("out.tls"), self.path("bad.txt")
            )


class TlsCacheTests(support.LoopbackTestCase):
    """Duplicate endpoints must cost one handshake, not one per link."""

    def test_one_handshake_per_distinct_endpoint(self) -> None:
        certs = _CertFiles(self.workdir)
        with support.tls_listener(certs.certfile, certs.keyfile) as server:
            lines = [
                _link(server.port, f"a{i}", insecure="1", sni="localhost")
                for i in range(12)
            ]
            lines.append(_link(server.port, "other", insecure="1", sni="localhost"))
            path = support.write_lines(self.path("in.txt"), lines)

            original = tls_test.tls_check
            calls: list[tuple] = []

            def counting(host, port, sni, timeout, *, insecure=False):  # type: ignore[no-untyped-def]
                calls.append((host, port, sni, insecure))
                return original(host, port, sni, timeout, insecure=insecure)

            tls_test.tls_check = counting
            self.addCleanup(setattr, tls_test, "tls_check", original)
            with self.quiet():
                stats = tls_test.tls_runner_threaded(
                    path,
                    self.path("out.tls"),
                    self.path("out.tls_faulty"),
                    timeout=3.0,
                    max_workers=4,
                )
            self.assertEqual(
                len(calls),
                1,
                f"{len(lines)} links over one endpoint issued {len(calls)} handshakes",
            )
            self.assertEqual(stats["ok"], len(lines))

    def test_verification_mode_is_part_of_the_cache_key(self) -> None:
        """insecure=1 and insecure=0 must not share a cached handshake."""
        certs = _CertFiles(self.workdir)
        with support.tls_listener(certs.certfile, certs.keyfile) as server:
            path = support.write_lines(
                self.path("in.txt"),
                [
                    _link(server.port, "verified", insecure="0", sni="localhost"),
                    _link(server.port, "insecure", insecure="1", sni="localhost"),
                ],
            )
            with self.quiet():
                stats = tls_test.tls_runner_threaded(
                    path,
                    self.path("out.tls"),
                    self.path("out.tls_faulty"),
                    timeout=3.0,
                    max_workers=2,
                )
        self.assertEqual(stats["tested"], 2)
        self.assertEqual(
            stats["ok"], 1, "only the insecure link may pass a self-signed server"
        )
        self.assertEqual(stats["failed"], 1)


class TlsScoredInputTests(support.LoopbackTestCase):
    """The TLS stage documents that it accepts '<ms>\\t<link>' input lines."""

    def test_a_leading_numeric_ms_is_read_as_the_planned_timing(self) -> None:
        """REGRESSION (bug 2): SPEC: input lines are '<ms>\\t<link>'; the ms must survive.

        ``tls_test._as_ms`` only accepted a field ending in ``_ms``, so the bare
        number that ``_render`` actually writes was discarded and the failure row
        reported a reason slug instead of the measurement the upstream stage
        already paid for. A real run had 100% of ``.tls_faulty`` lines starting
        with ``cert``/``unreachable`` rather than a number.

        The expected text is ``"99.90"``, not ``"99.9"``: the failure artifact
        renders every field through ``_render``, which canonicalises to two
        decimals, and that canonical form is what makes the artifact round-trip.
        """
        dead = support.closed_port()
        path = support.write_lines(self.path("in.txt"), [f"99.9\t{_link(dead, 'a')}"])
        with self.quiet():
            tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=2,
            )
        rows = support.read_lines(self.path("out.tls_faulty"))
        self.assertEqual(len(rows), 1)
        field = rows[0].split("\t", 1)[0]
        self.assertEqual(
            field,
            "99.90",
            "the planned millisecond value must be carried into the faulty row",
        )
        self.assertEqual(float(field), 99.9)

    def test_a_rendered_row_reads_back_as_its_own_planned_timing(self) -> None:
        """The artifact this module writes must be input it can read back.

        Bug 2 was a write/read disagreement between ``_render`` and ``_as_ms``, so
        pin the round trip directly rather than only a hand-written field.
        """
        dead = support.closed_port()
        rendered = tls_test._render(99.9)
        path = support.write_lines(
            self.path("in.txt"), [f"{rendered}\t{_link(dead, 'a')}"]
        )
        with self.quiet():
            tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=2,
            )
        field = support.read_lines(self.path("out.tls_faulty"))[0].split("\t", 1)[0]
        self.assertEqual(field, rendered, "the field must survive a write/read cycle")

    def test_a_leading_suffixed_ms_field_is_accepted(self) -> None:
        """``_ms`` is kept as an accepted legacy spelling, not as the primary one."""
        dead = support.closed_port()
        path = support.write_lines(
            self.path("in.txt"), [f"99.9_ms\t{_link(dead, 'a')}"]
        )
        with self.quiet():
            tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=2,
            )
        rows = support.read_lines(self.path("out.tls_faulty"))
        self.assertEqual(rows[0].split("\t", 1)[0], "99.90")

    def test_the_primary_format_is_a_bare_number_with_no_suffix(self) -> None:
        """Guard the specific regression: no spelling but the bare number."""
        self.assertNotIn("_ms", tls_test._render(99.9))
        self.assertEqual(tls_test._as_ms("99.9"), 99.9)
        self.assertEqual(tls_test._as_ms("7"), 7.0)
        self.assertEqual(tls_test._as_ms("0"), 0.0)


class SplitLineTests(unittest.TestCase):
    """REGRESSION (bug 1): when is a tab a separator, and when is it link text?

    ``_split_line`` used to split on the first tab unconditionally. A bare link
    whose fragment contains a tab -- which is ordinary input, because the
    pipeline hands this stage BARE links -- was destroyed and the tail filed as a
    ``parse`` failure. The rule is now "a tab separates only when the text before
    it is a score or a known reason slug", mirroring
    :func:`links._strip_scored_prefix` but kept local so this module can also
    recognise the slug fields its own failure artifact writes.
    """

    def _split(self, line: str) -> tuple[float | None, str]:
        return tls_test._split_line(line)  # type: ignore[no-any-return]

    def test_bare_link_with_an_embedded_tab_survives_intact(self) -> None:
        """The exact link from the bug report."""
        self.assertEqual(
            self._split(UNPARSEABLE_TAB_LINK), (None, UNPARSEABLE_TAB_LINK)
        )
        self.assertEqual(self._split(A_TAB_LINK), (None, A_TAB_LINK))

    def test_scored_line_keeps_a_tab_inside_its_link(self) -> None:
        self.assertEqual(self._split(f"99.9\t{A_TAB_LINK}"), (99.9, A_TAB_LINK))

    def test_only_the_first_tab_is_consumed_on_a_scored_line(self) -> None:
        self.assertEqual(self._split("1\ta\tb"), (1.0, "a\tb"))

    def test_a_known_reason_slug_prefix_is_stripped_without_a_timing(self) -> None:
        """This module's own failure artifact is valid input to this stage."""
        for slug in sorted(tls_test.ERROR_SLUGS):
            with self.subTest(slug=slug):
                self.assertEqual(
                    self._split(f"{slug}\t{A_TAB_LINK}"), (None, A_TAB_LINK)
                )

    def test_a_numeric_looking_link_prefix_is_not_mangled(self) -> None:
        """The rejection of the naive "non-empty first field" fix.

        A bare ``host:port`` link starts with digits, and a fragment may follow a
        tab. Nothing is stripped unless the field is a bare number or a slug, so
        the whole line -- link included -- is kept.
        """
        for line in (
            "127.0.0.1:9002\t#note",
            "127.0.0.1:9002\tsome other text",
            "127.0.0.1\t#note",
            f"1e3\t{A_TAB_LINK}",
        ):
            with self.subTest(line=line):
                self.assertEqual(self._split(line), (None, line))

    def test_the_only_accepted_ambiguity_is_a_bare_number(self) -> None:
        """``"9002\\t<link>"`` is deliberately read as a score, not a link.

        A bare integer followed by a tab is indistinguishable from a scored
        artifact line, and ``<ms>\\t<link>`` is the agreed format, so the score
        reading wins. Nothing that actually looks like a link is affected: a
        link always carries a ``:`` or ``@`` before any tab.
        """
        self.assertEqual(self._split(f"9002\t{A_TAB_LINK}"), (9002.0, A_TAB_LINK))

    def test_rejected_leading_fields_never_corrupt_the_link(self) -> None:
        """Negative, NaN, infinite, oversized and non-numeric fields.

        Each of these must be rejected by the score check, which means the line is
        kept WHOLE -- the link is never split away, and no timing is invented.
        """
        for field in (
            "-1",
            "-0.5",
            "nan",
            "NaN",
            "inf",
            "-inf",
            "Infinity",
            "1e3",
            "12.5ms",
            "n/a",
            "",
            "   ",
            "1,5",
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    self._split(f"{field}\t{A_TAB_LINK}"),
                    (None, f"{field}\t{A_TAB_LINK}"),
                )

    def test_a_rejected_field_reports_no_timing(self) -> None:
        as_ms = tls_test._as_ms
        for field in (
            "-1",
            "-0.5",
            "nan",
            "inf",
            "-inf",
            "1e3",
            "12.5ms",
            "n/a",
            "",
            "   ",
        ):
            with self.subTest(field=field):
                self.assertIsNone(as_ms(field), f"{field!r} must not read as a timing")

    def test_bare_and_scored_and_tabbed_links_all_survive_the_stage(self) -> None:
        """End to end through tls_runner_threaded, byte-for-byte.

        Three input shapes at once: a bare link carrying a tab, an ordinary
        scored line, and a scored line whose LINK also carries a tab. The host is
        a real one, so each line parses and is actually probed -- if the tab were
        treated as a separator, the bare line would be truncated and would land in
        the faulty artifact as a ``parse`` failure instead.
        """
        bare = A_TAB_LINK
        plain = "vless://u@127.0.0.1:9003?a=1#plain"
        scored_tabbed = "vless://u@127.0.0.1:9004?a=1#tab\there"
        lines = [bare, f"12.5\t{plain}", f"34.5\t{scored_tabbed}"]
        expected = {bare, plain, scored_tabbed}

        original = tls_test.tls_check
        tls_test.tls_check = lambda *a, **k: (True, 1.0, None)  # type: ignore[assignment]
        self.addCleanup(setattr, tls_test, "tls_check", original)

        with support.workspace() as workdir, support.silence():
            path = support.write_lines(os.path.join(workdir, "in.txt"), lines)
            stats = tls_test.tls_runner_threaded(
                path,
                os.path.join(workdir, "out.tls"),
                os.path.join(workdir, "out.tls_faulty"),
                timeout=1.0,
                max_workers=2,
            )
            written = [
                row.split("\t", 1)[1]
                for row in support.read_lines(os.path.join(workdir, "out.tls"))
            ]
            faulty = support.read_lines(os.path.join(workdir, "out.tls_faulty"))
        self.assertEqual(
            stats["ok"], 3, "all three links must be probed, not filed as parse"
        )
        self.assertEqual(
            stats["failed"], 0, f"nothing should be faulty, got {faulty!r}"
        )
        self.assertEqual(sorted(written), sorted(expected))

    def test_the_bug_report_link_survives_even_when_it_cannot_parse(self) -> None:
        """The literal string from the bug report, end to end.

        ``h`` is not a valid host for :func:`links.parse_link`, so this link is
        (correctly) a ``parse`` failure -- but its TEXT must reach the faulty
        artifact whole. Before the fix the head was swallowed and only the
        fragment tail ``here`` was written, losing the link entirely.
        """
        line = UNPARSEABLE_TAB_LINK
        original = tls_test.tls_check
        tls_test.tls_check = lambda *a, **k: (True, 1.0, None)  # type: ignore[assignment]
        self.addCleanup(setattr, tls_test, "tls_check", original)

        with support.workspace() as workdir, support.silence():
            path = support.write_lines(os.path.join(workdir, "in.txt"), [line])
            stats = tls_test.tls_runner_threaded(
                path,
                os.path.join(workdir, "out.tls"),
                os.path.join(workdir, "out.tls_faulty"),
                timeout=1.0,
                max_workers=1,
            )
            faulty = support.read_lines(os.path.join(workdir, "out.tls_faulty"))
        self.assertEqual(stats, {"tested": 1, "ok": 0, "failed": 1})
        self.assertEqual(len(faulty), 1)
        self.assertEqual(faulty[0].split("\t", 1)[0], "parse")
        self.assertEqual(
            faulty[0].split("\t", 1)[1],
            line,
            "the whole link, tab and all, must be preserved",
        )


class ConfigOverrideTests(support.LoopbackTestCase):
    """REGRESSION (bug 3): ``Config.apply_overrides`` must reach this stage.

    ``timeout`` and ``max_workers`` were default arguments, and a default
    argument is evaluated once at function-definition time. The CLI's
    ``--set TLS_TIMEOUT=...`` therefore had no effect on the TLS stage at all.
    They now default to ``None`` and are resolved from Config at call time, the
    same way ``netprobe`` does it.
    """

    def setUp(self) -> None:
        super().setUp()
        self._saved = (Config.TLS_TIMEOUT, Config.TLS_THREADS)
        self.addCleanup(self._restore)
        seen: dict[str, object] = {"timeouts": set()}
        self.seen = seen

        original = tls_test.tls_check

        def recording(host, port, sni, timeout, *, insecure=False):  # type: ignore[no-untyped-def]
            seen["timeouts"].add(timeout)  # type: ignore[union-attr]
            return (True, 1.0, None)

        tls_test.tls_check = recording
        self.addCleanup(setattr, tls_test, "tls_check", original)

        pool_cls = tls_test.ThreadPoolExecutor

        class RecordingPool(pool_cls):  # type: ignore[valid-type, misc]
            def __init__(self, max_workers=None, **kwargs):  # type: ignore[no-untyped-def]
                seen["max_workers"] = max_workers
                super().__init__(max_workers=max_workers, **kwargs)

        tls_test.ThreadPoolExecutor = RecordingPool  # type: ignore[misc]
        self.addCleanup(setattr, tls_test, "ThreadPoolExecutor", pool_cls)

    def _restore(self) -> None:
        Config.TLS_TIMEOUT, Config.TLS_THREADS = self._saved

    def _run(
        self, *, timeout: float | None = None, max_workers: int | None = None
    ) -> dict[str, int]:
        # Three DISTINCT endpoints: the stage sizes its pool as
        # ``min(max_workers, len(todo))``, so a single-endpoint input would clamp
        # the worker count to 1 and hide the very thing under test.
        path = support.write_lines(
            self.path("in.txt"), [_link(9002 + i, chr(97 + i)) for i in range(3)]
        )
        with self.quiet():
            return tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=timeout,
                max_workers=max_workers,
            )

    def test_overrides_reach_the_stage_when_no_arguments_are_passed(self) -> None:
        Config.apply_overrides(["TLS_TIMEOUT=9.5", "TLS_THREADS=7"])
        self._run()
        self.assertEqual(self.seen["timeouts"], {9.5}, "TLS_TIMEOUT was ignored")
        self.assertEqual(
            self.seen["max_workers"], 3, "TLS_THREADS=7 was ignored (clamped to 3)"
        )

    def test_defaults_come_from_config_when_nothing_is_overridden(self) -> None:
        self._run()
        self.assertEqual(self.seen["timeouts"], {float(Config.TLS_TIMEOUT)})
        self.assertEqual(
            self.seen["max_workers"],
            min(int(Config.TLS_THREADS), 3),
        )

    def test_explicit_arguments_still_win_over_config(self) -> None:
        """start.py passes both explicitly; that call must keep working unchanged."""
        Config.apply_overrides(["TLS_TIMEOUT=9.5", "TLS_THREADS=7"])
        self._run(timeout=0.25, max_workers=2)
        self.assertEqual(self.seen["timeouts"], {0.25})
        self.assertEqual(self.seen["max_workers"], 2)

    def test_start_py_shaped_call_still_works(self) -> None:
        """The exact call shape start.py uses: three positional, two keyword."""
        Config.apply_overrides(["TLS_TIMEOUT=9.5", "TLS_THREADS=7"])
        path = support.write_lines(
            self.path("in.txt"), [_link(9002 + i, chr(97 + i)) for i in range(3)]
        )
        with self.quiet():
            stats = tls_test.tls_runner_threaded(
                str(path),
                str(self.path("out.tls")),
                str(self.path("out.tls_faulty")),
                timeout=float(Config.TLS_TIMEOUT),
                max_workers=7,
            )
        self.assertEqual(stats["tested"], 3)
        self.assertEqual(self.seen["timeouts"], {9.5})
        self.assertEqual(self.seen["max_workers"], 3)

    def test_resolvers_floor_the_worker_count(self) -> None:
        self.assertEqual(tls_test._resolve_workers(0), 1)
        self.assertEqual(tls_test._resolve_workers(-5), 1)
        self.assertEqual(tls_test._resolve_timeout(0.0), 0.0)


class SlugVocabularyTests(unittest.TestCase):
    """An undocumented slug is a bug: the emitted set must be declared."""

    def test_documented_slug_set_is_exact(self) -> None:
        self.assertEqual(
            tls_test.ERROR_SLUGS,
            BASE_SLUGS | EXTENSION_SLUGS,
            "the module's declared slug set drifted from the documented one",
        )

    def test_no_slug_leaks_out_of_the_classifiers(self) -> None:
        for name in ("_oserror_slug", "_ssl_slug"):
            classifier = getattr(tls_test, name)
            for exc in (
                OSError(111, "Connection refused"),
                OSError(113, "No route to host"),
                TimeoutError(),
                socket.gaierror(-2, "Name or service not known"),
                ssl.SSLCertVerificationError("bad cert"),
                ssl.SSLError(1, "[SSL] HANDSHAKE_FAILURE"),
                ssl.SSLError(1, "unrelated"),
                ValueError("something else entirely"),
            ):
                with self.subTest(classifier=name, exc=repr(exc)):
                    self.assertIn(classifier(exc), tls_test.ERROR_SLUGS)


class WorkerExceptionTests(support.LoopbackTestCase):
    """A raising worker must be recorded, must not poison the stage, and must not vanish."""

    def test_a_raising_worker_is_recorded_and_reported(self) -> None:
        seen: list[str] = []

        def exploding(host, port, sni, timeout, *, insecure=False):  # type: ignore[no-untyped-def]
            seen.append(f"{host}:{port}")
            raise RuntimeError("worker exploded")

        original = tls_test.tls_check
        tls_test.tls_check = exploding
        self.addCleanup(setattr, tls_test, "tls_check", original)

        lines = [_link(9002, "a"), _link(9003, "b")]
        path = support.write_lines(self.path("in.txt"), lines)
        # support.silence() is entered by setUp and yields the buffer it captures
        # stdout/stderr into; quiet() hands that buffer back.
        buffer = cast("io.StringIO", self.quiet())
        stats = tls_test.tls_runner_threaded(
            path,
            self.path("out.tls"),
            self.path("out.tls_faulty"),
            timeout=0.5,
            max_workers=2,
        )
        self.assertEqual(
            sorted(seen),
            ["127.0.0.1:9002", "127.0.0.1:9003"],
            "one call per distinct endpoint",
        )
        self.assertEqual(stats["tested"], 2)
        self.assertEqual(stats["ok"], 0)
        self.assertEqual(
            stats["failed"], 2, "the raising endpoints are failures, not a crash"
        )
        for row in support.read_lines(self.path("out.tls_faulty")):
            self.assertIn(row.split("\t", 1)[0], tls_test.ERROR_SLUGS)
        self.assertIn(
            "RuntimeError",
            buffer.getvalue(),
            "the exception must be reported, not swallowed",
        )
        self.assertIn("worker exploded", buffer.getvalue())

    def test_a_raising_worker_does_not_stop_later_endpoints(self) -> None:
        """One bad endpoint must not take the rest of the batch with it."""

        def selective(host, port, sni, timeout, *, insecure=False):  # type: ignore[no-untyped-def]
            if port == 9002:
                raise ValueError("this endpoint is cursed")
            if port == 9003:
                return (True, 4.0, None)
            return (False, None, "refused")

        original = tls_test.tls_check
        tls_test.tls_check = selective
        self.addCleanup(setattr, tls_test, "tls_check", original)

        lines = [_link(9002, "cursed"), _link(9003, "fine"), _link(9004, "dead")]
        path = support.write_lines(self.path("in.txt"), lines)
        with self.quiet():
            stats = tls_test.tls_runner_threaded(
                path,
                self.path("out.tls"),
                self.path("out.tls_faulty"),
                timeout=0.5,
                max_workers=2,
            )
        self.assertEqual(stats, {"tested": 3, "ok": 1, "failed": 2})
        self.assertEqual(
            [row.split("\t", 1)[1] for row in support.read_lines(self.path("out.tls"))],
            [lines[1]],
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
