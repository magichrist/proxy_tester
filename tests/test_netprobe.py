"""Tests for netprobe.py -- the timed TCP-connect prober.

Every endpoint used here is a loopback socket started by :mod:`support`, so the
module is exercised for real (real connects, real refusals, real JSONL files)
without a single packet leaving the machine. ``support.install_network_guard``
makes that a hard guarantee rather than a promise.
"""

from __future__ import annotations

import json
import socket
import unittest

try:  # discovery puts tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

import netprobe

#: The exact key set of a timings.jsonl record, per docs/REFACTOR_SPEC.md.
TIMINGS_KEYS = {"endpoint", "host", "port", "ok", "ms", "error"}

#: Slugs the module is allowed to emit.
VALID_SLUGS = frozenset({"timeout", "refused", "dns", "unreachable", "tls", "other"})


def _link(host: str, port: int, tag: str = "n") -> str:
    return f"vless://uuid-{tag}@{host}:{port}#note-{tag}"


class ProbeEndpointShapeTests(unittest.TestCase):
    """probe_endpoint returns a 3-tuple on every path and never raises."""

    def test_returns_three_tuple_on_a_closed_port(self) -> None:
        result = netprobe.probe_endpoint("127.0.0.1", support.closed_port(), 0.5)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        ok, ms, error = result
        self.assertIs(ok, False)
        self.assertIsNone(ms, "a failed probe must report ms=None, never a number")
        self.assertEqual(error, "refused")
        self.assertIn(error, VALID_SLUGS)

    def test_dns_failure_reports_the_dns_slug(self) -> None:
        """A resolution failure must surface as 'dns', not as an exception.

        ``socket.create_connection`` is stubbed rather than a real name used:
        the suite's loopback guard refuses any non-loopback address, and a live
        DNS query would be an outbound request.
        """
        original = socket.create_connection

        def refuse(*args: object, **kwargs: object):
            raise socket.gaierror(-2, "Name or service not known")

        socket.create_connection = refuse  # type: ignore[assignment]
        self.addCleanup(setattr, socket, "create_connection", original)
        ok, ms, error = netprobe.probe_endpoint("nx.proxy.example", 443, 0.5)
        self.assertEqual((ok, ms, error), (False, None, "dns"))

    def test_succeeds_against_a_real_local_listener(self) -> None:
        with support.tcp_listener() as listener:
            ok, ms, error = netprobe.probe_endpoint(listener.host, listener.port, 2.0)
        self.assertIs(ok, True)
        self.assertIsNone(error)
        assert isinstance(ms, float)
        self.assertGreaterEqual(ms, 0.0)
        self.assertLess(ms, 2000.0, "a loopback connect must be fast")

    def test_never_raises_on_junk_arguments(self) -> None:
        junk = [
            ("", 443, 0.1),
            ("127.0.0.1", -1, 0.1),
            ("127.0.0.1", 0, 0.1),
            ("127.0.0.1", 70000, 0.1),
            ("127.0.0.1", 65535, 0.001),
        ]
        for host, port, timeout in junk:
            with self.subTest(host=host, port=port):
                result = netprobe.probe_endpoint(host, port, timeout)
                self.assertIsInstance(result, tuple)
                self.assertEqual(len(result), 3)
                ok, ms, error = result
                self.assertIn(ok, (True, False))
                if ok:
                    assert isinstance(ms, float)
                    self.assertIsNone(error)
                else:
                    self.assertIsNone(ms)
                    assert isinstance(error, str)
                    self.assertIn(error, VALID_SLUGS)

    def test_result_is_always_indexable_without_a_type_check(self) -> None:
        """Correctness requirement 1: False[1] can never happen."""
        result = netprobe.probe_endpoint("127.0.0.1", support.closed_port(), 0.5)
        self.assertFalse(result[0])
        # Indexing element 1 without guarding on element 0 must not raise.
        self.assertIsNone(result[1])
        self.assertIsInstance(result[2], str)


class ProbeCacheTests(support.LoopbackTestCase):
    """The measurement cache is the central performance claim of the refactor."""

    ENDPOINTS = 3
    LINKS_PER_ENDPOINT = 60

    def _input(self) -> tuple[str, list[str], list[int]]:
        with support.tcp_listener() as first, support.tcp_listener() as second:
            ports = [first.port, second.port, support.closed_port()]
            lines = []
            for port in ports:
                for index in range(self.LINKS_PER_ENDPOINT):
                    lines.append(_link("127.0.0.1", port, f"{port}-{index}"))
            path = support.write_lines(self.path("in.de"), lines)
            return path, lines, ports

    def test_many_links_over_few_endpoints_issue_few_connects(self) -> None:
        path, lines, _ports = self._input()
        total_links = len(lines)
        real_probe = netprobe.probe_endpoint
        connects: list[tuple] = []

        def counting(host: str, port: int, timeout: float):
            connects.append((host, port))
            return real_probe(host, port, timeout)

        netprobe.probe_endpoint = counting
        self.addCleanup(setattr, netprobe, "probe_endpoint", real_probe)

        with self.quiet():
            stats = netprobe.probe_file(
                path,
                self.path("out.alive"),
                self.path("out.timings.jsonl"),
                timeout=1.0,
                max_workers=4,
            )

        self.assertEqual(stats["links_in"], total_links)
        self.assertEqual(stats["endpoints"], self.ENDPOINTS)
        self.assertEqual(
            len(connects),
            self.ENDPOINTS,
            f"{total_links} links over {self.ENDPOINTS} endpoints must issue "
            f"{self.ENDPOINTS} connects, not {len(connects)}",
        )
        self.assertLess(len(connects) * 10, total_links)
        self.assertEqual(len(set(connects)), self.ENDPOINTS)
        self.assertEqual(stats["links_alive"] + stats["links_dead"], total_links)

    def test_preseeded_timings_issue_zero_connects(self) -> None:
        path, lines, ports = self._input()
        real_probe = netprobe.probe_endpoint
        connects: list[tuple] = []

        def counting(host: str, port: int, timeout: float):
            connects.append((host, port))
            return real_probe(host, port, timeout)

        netprobe.probe_endpoint = counting
        self.addCleanup(setattr, netprobe, "probe_endpoint", real_probe)

        seed = {netprobe.endpoint_str("127.0.0.1", port): 12.5 for port in ports}
        with self.quiet():
            stats = netprobe.probe_file(
                path,
                self.path("out.alive"),
                self.path("out.timings.jsonl"),
                timeout=1.0,
                max_workers=4,
                timings=seed,
            )
        self.assertEqual(connects, [], "a pre-seeded endpoint must never be re-probed")
        self.assertEqual(stats["links_alive"], len(lines))
        self.assertEqual(stats["endpoints_dead"], 0)

    def test_preseeded_failure_is_trusted_and_marked_dead(self) -> None:
        path, lines, ports = self._input()
        seed = {netprobe.endpoint_str("127.0.0.1", port): None for port in ports}
        with self.quiet():
            stats = netprobe.probe_file(
                path,
                self.path("out.alive"),
                self.path("out.timings.jsonl"),
                timeout=1.0,
                max_workers=4,
                timings=seed,
            )
        self.assertEqual(stats["links_alive"], 0)
        self.assertEqual(stats["links_dead"], len(lines))
        self.assertEqual(support.read_lines(self.path("out.alive")), [])


class ProbeFileOutputTests(support.LoopbackTestCase):
    """Artifacts written by the probe stage."""

    def test_alive_file_preserves_input_order_and_raw_link_text(self) -> None:
        with support.tcp_listener() as listener:
            lines = [_link("127.0.0.1", listener.port, f"a{i}") for i in range(5)] + [
                "junk line",
                _link("127.0.0.1", support.closed_port(), "dead"),
            ]
            path = support.write_lines(self.path("in.de"), lines)
            with self.quiet():
                stats = netprobe.probe_file(
                    path,
                    self.path("out.alive"),
                    self.path("out.timings.jsonl"),
                    timeout=1.0,
                    max_workers=4,
                )
        self.assertEqual(support.read_lines(self.path("out.alive")), lines[:5])
        self.assertEqual(
            stats["links_in"], 6, "the unparseable line is excluded from links_in"
        )

    def test_timings_jsonl_record_shape(self) -> None:
        with support.tcp_listener() as listener:
            dead = support.closed_port()
            path = support.write_lines(
                self.path("in.de"),
                [
                    _link("127.0.0.1", listener.port, "up"),
                    _link("127.0.0.1", dead, "down"),
                ],
            )
            with self.quiet():
                netprobe.probe_file(
                    path,
                    self.path("out.alive"),
                    self.path("out.timings.jsonl"),
                    timeout=1.0,
                    max_workers=2,
                )
        records = [
            json.loads(line)
            for line in support.read_lines(self.path("out.timings.jsonl"))
        ]
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(set(record), TIMINGS_KEYS)
            self.assertEqual(
                record["endpoint"],
                netprobe.endpoint_str(record["host"], record["port"]),
            )
        by_port = {record["port"]: record for record in records}
        up = by_port[listener.port]
        self.assertIs(up["ok"], True)
        self.assertIsInstance(up["ms"], float)
        self.assertIsNone(up["error"])
        down = by_port[dead]
        self.assertIs(down["ok"], False)
        self.assertIsNone(down["ms"], "ms must be null on failure, not 0")
        self.assertIsInstance(down["error"], str)
        self.assertIn(down["error"], VALID_SLUGS)

    def test_output_directories_are_created(self) -> None:
        path = support.write_lines(
            self.path("in.de"), [_link("127.0.0.1", support.closed_port(), "d")]
        )
        nested_alive = self.path("a/b/c/out.alive")
        nested_timings = self.path("a/b/c/out.timings.jsonl")
        with self.quiet():
            netprobe.probe_file(
                path, nested_alive, nested_timings, timeout=0.5, max_workers=2
            )
        import os

        self.assertTrue(os.path.exists(nested_timings))

    def test_missing_input_file_raises(self) -> None:
        with self.assertRaises(OSError):
            netprobe.probe_file(
                self.path("absent.de"),
                self.path("o.alive"),
                self.path("o.jsonl"),
                timeout=0.5,
                max_workers=2,
            )


class LoadTimingsTests(support.LoopbackTestCase):
    """The timings.jsonl contract, in both directions."""

    RECORDS = [
        {
            "endpoint": "127.0.0.1:443",
            "host": "127.0.0.1",
            "port": 443,
            "ok": True,
            "ms": 42.31,
            "error": None,
        },
        {
            "endpoint": "127.0.0.1:8443",
            "host": "127.0.0.1",
            "port": 8443,
            "ok": False,
            "ms": None,
            "error": "timeout",
        },
        {
            "endpoint": "[::1]:443",
            "host": "::1",
            "port": 443,
            "ok": True,
            "ms": 0.5,
            "error": None,
        },
    ]

    def _write(self, records: list[dict]) -> str:
        return support.write_lines(
            self.path("t.jsonl"),
            [json.dumps(record, separators=(",", ":")) for record in records],
        )

    def test_round_trips_the_documented_contract(self) -> None:
        path = self._write(self.RECORDS)
        timings = netprobe.load_timings(path)
        self.assertEqual(
            timings,
            {"127.0.0.1:443": 42.31, "127.0.0.1:8443": None, "[::1]:443": 0.5},
        )

    def test_round_trips_against_probe_file_output(self) -> None:
        with support.tcp_listener() as listener:
            dead = support.closed_port()
            path = support.write_lines(
                self.path("in.de"),
                [
                    _link("127.0.0.1", listener.port, "up"),
                    _link("127.0.0.1", dead, "down"),
                ],
            )
            with self.quiet():
                netprobe.probe_file(
                    path,
                    self.path("out.alive"),
                    self.path("out.timings.jsonl"),
                    timeout=1.0,
                    max_workers=2,
                )
            timings = netprobe.load_timings(self.path("out.timings.jsonl"))
        self.assertEqual(len(timings), 2)
        self.assertIsNotNone(timings[netprobe.endpoint_str("127.0.0.1", listener.port)])
        self.assertIsNone(timings[netprobe.endpoint_str("127.0.0.1", dead)])

    def test_missing_file_yields_empty_mapping(self) -> None:
        self.assertEqual(netprobe.load_timings(self.path("absent.jsonl")), {})

    def test_malformed_lines_are_skipped_not_fatal(self) -> None:
        path = support.write_lines(
            self.path("t.jsonl"),
            [
                "not json at all",
                "[]",
                json.dumps(
                    {"host": "127.0.0.1", "port": 1}
                ),  # no endpoint key: skipped
                json.dumps({"endpoint": 5, "ms": 1.0}),  # endpoint not a str: skipped
                json.dumps(
                    {"endpoint": "127.0.0.1:443", "ms": 7.0, "ok": True, "error": None}
                ),
            ],
        )
        self.assertEqual(netprobe.load_timings(path), {"127.0.0.1:443": 7.0})

    def test_a_record_with_an_unreadable_ms_reads_as_a_failure(self) -> None:
        """A corrupt measurement must reject its links, not silently keep them."""
        path = support.write_lines(
            self.path("t.jsonl"),
            [json.dumps({"endpoint": "127.0.0.1:9", "ms": "fast"})],
        )
        self.assertEqual(netprobe.load_timings(path), {"127.0.0.1:9": None})

    def test_endpoint_str_brackets_ipv6_and_matches_links(self) -> None:
        import links

        self.assertEqual(netprobe.endpoint_str("::1", 443), "[::1]:443")
        self.assertEqual(netprobe.endpoint_str("127.0.0.1", 443), "127.0.0.1:443")
        parsed = links.parse_link("vless://u@[2001:db8::1]:443#n")
        assert parsed is not None
        self.assertEqual(
            parsed.endpoint_str,
            netprobe.endpoint_str(parsed.host, parsed.port),
            "the two endpoint key builders must never drift",
        )


class FilterByLatencyTests(support.LoopbackTestCase):
    """filter_by_latency must never silently truncate the alive file."""

    def test_empty_timings_file_raises(self) -> None:
        alive = support.write_lines(
            self.path("in.alive"), [_link("127.0.0.1", 443, "a")]
        )
        timings = support.write_lines(self.path("t.jsonl"), [])
        out = self.path("out.filtered")
        with self.assertRaises(ValueError) as ctx:
            netprobe.filter_by_latency(alive, out, timings, max_ms=800.0)
        self.assertIn("no measurements", str(ctx.exception))
        self.assertFalse(
            __import__("os").path.exists(out),
            "the filtered file must not be created from an empty measurement set",
        )

    def test_absent_timings_file_raises(self) -> None:
        alive = support.write_lines(
            self.path("in.alive"), [_link("127.0.0.1", 443, "a")]
        )
        out = self.path("out.filtered")
        with self.assertRaises(ValueError):
            netprobe.filter_by_latency(
                alive, out, self.path("absent.jsonl"), max_ms=800.0
            )
        self.assertFalse(__import__("os").path.exists(out))

    def test_an_existing_output_is_not_truncated_when_measurements_are_missing(
        self,
    ) -> None:
        alive = support.write_lines(
            self.path("in.alive"), [_link("127.0.0.1", 443, "a")]
        )
        out = support.write_lines(self.path("out.filtered"), ["PREVIOUS RUN SURVIVED"])
        timings = support.write_lines(self.path("t.jsonl"), [])
        with self.assertRaises(ValueError):
            netprobe.filter_by_latency(alive, out, timings, max_ms=800.0)
        self.assertEqual(support.read_lines(out), ["PREVIOUS RUN SURVIVED"])

    def test_empty_input_with_no_measurements_does_not_raise(self) -> None:
        """No work to do is not the same as a truncated result."""
        alive = support.write_lines(self.path("in.alive"), [])
        timings = support.write_lines(self.path("t.jsonl"), [])
        with self.quiet():
            stats = netprobe.filter_by_latency(
                alive, self.path("out.filtered"), timings, max_ms=800.0
            )
        self.assertEqual(
            stats, {"links_in": 0, "kept": 0, "rejected": 0, "links_dropped": 0}
        )

    def test_splits_on_the_threshold(self) -> None:
        with support.tcp_listener() as fast, support.tcp_listener() as slow:
            lines = [_link("127.0.0.1", fast.port, f"f{i}") for i in range(4)] + [
                _link("127.0.0.1", slow.port, f"s{i}") for i in range(3)
            ]
            alive = support.write_lines(self.path("in.alive"), lines)
            records = [
                {
                    "endpoint": netprobe.endpoint_str("127.0.0.1", fast.port),
                    "host": "127.0.0.1",
                    "port": fast.port,
                    "ok": True,
                    "ms": 5.0,
                    "error": None,
                },
                {
                    "endpoint": netprobe.endpoint_str("127.0.0.1", slow.port),
                    "host": "127.0.0.1",
                    "port": slow.port,
                    "ok": True,
                    "ms": 900.0,
                    "error": None,
                },
            ]
            timings = support.write_lines(
                self.path("t.jsonl"),
                [json.dumps(r, separators=(",", ":")) for r in records],
            )
            with self.quiet():
                stats = netprobe.filter_by_latency(
                    alive, self.path("out.filtered"), timings, max_ms=800.0
                )
        self.assertEqual(stats["links_in"], 7)
        self.assertEqual(stats["kept"], 4)
        self.assertEqual(stats["rejected"], 3)
        self.assertEqual(stats["kept"] + stats["rejected"], stats["links_in"])
        self.assertEqual(len(support.read_lines(self.path("out.filtered"))), 4)

    def test_unmeasured_endpoint_is_rejected_not_kept(self) -> None:
        with support.tcp_listener() as listener:
            lines = [_link("127.0.0.1", listener.port, "a")]
            alive = support.write_lines(self.path("in.alive"), lines)
            records = [
                {
                    "endpoint": "some.other.endpoint:1",
                    "host": "some.other.endpoint",
                    "port": 1,
                    "ok": True,
                    "ms": 1.0,
                    "error": None,
                }
            ]
            timings = support.write_lines(
                self.path("t.jsonl"), [json.dumps(records[0], separators=(",", ":"))]
            )
            with self.quiet():
                stats = netprobe.filter_by_latency(
                    alive, self.path("out.filtered"), timings, max_ms=800.0
                )
        self.assertEqual(stats["kept"], 0)
        self.assertEqual(stats["rejected"], 1)

    def test_injected_timings_mapping_is_used_in_preference_to_the_file(self) -> None:
        with support.tcp_listener() as listener:
            lines = [_link("127.0.0.1", listener.port, "a")]
            alive = support.write_lines(self.path("in.alive"), lines)
            timings = support.write_lines(self.path("t.jsonl"), [])
            with self.quiet():
                stats = netprobe.filter_by_latency(
                    alive,
                    self.path("out.filtered"),
                    timings,
                    max_ms=800.0,
                    timings={netprobe.endpoint_str("127.0.0.1", listener.port): 3.0},
                )
        self.assertEqual(stats["kept"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
