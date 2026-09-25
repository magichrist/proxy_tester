"""The consolidation invariant: every link lands in exactly one bucket.

This is correctness requirement 3 of docs/REFACTOR_SPEC.md and the entire point
of the refactor. The old code silently discarded every link that failed a stage
after it had parsed, so a run could report "0 proxies found" without anyone
being able to say how many were lost.

These tests drive the real four stages -- decode, probe, latency filter, TLS --
over a synthetic input deliberately built so that every bucket is non-empty:
unparseable lines, duplicates, dead endpoints, over-threshold endpoints, fast
endpoints, TLS successes and TLS failures. Then they check the two conservation
identities and that no link text appears twice or zero times.

Nothing here reaches the network: the probe stage is given a pre-seeded
timings mapping covering every endpoint, and the TLS stage has its handshake
stubbed.
"""

from __future__ import annotations

import collections
import unittest
from typing import Mapping

try:  # discovery puts tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

import links
import netprobe
import tls_test

#: Probe results injected for the synthetic endpoints, in milliseconds.
#: None means "the connect failed", i.e. the endpoint is dead.
FAST_MS = 12.0
SLOW_MS = 400.0
LATENCY_THRESHOLD_MS = 100.0


class PipelineRun:
    """The result of one offline end-to-end run over a synthetic link list."""

    def __init__(self, workdir: str, lines: list[str], seed: "Mapping[str, float | None]",
                 latency_ms: float, tls_latency: "Mapping[int, float | None] | None" = None) -> None:
        self.workdir = workdir
        self.input_path = support.write_lines(f"{workdir}/in.txt", lines)
        self.alive_path = f"{workdir}/in.txt.de.alive"
        self.filtered_path = f"{workdir}/in.txt.de.alive.filtered"
        self.tls_path = f"{workdir}/in.txt.de.alive.filtered.tls"
        self.faulty_path = f"{workdir}/in.txt.de.alive.filtered.tls_faulty"
        self.timings_path = f"{workdir}/in.txt.timings.jsonl"
        self.latency_ms = latency_ms

        _links, self.load_stats = links.load_unique_detailed(self.input_path)
        self.probe_stats = netprobe.probe_file(
            self.input_path, self.alive_path, self.timings_path,
            timeout=0.5, max_workers=4, timings=seed,
        )
        self.filter_stats = netprobe.filter_by_latency(
            self.alive_path, self.filtered_path, self.timings_path,
            max_ms=latency_ms, timings=netprobe.load_timings(self.timings_path),
        )
        if tls_latency is None:
            self.tls_stats = tls_test.tls_runner_threaded(
                self.filtered_path, self.tls_path, self.faulty_path,
                timeout=0.5, max_workers=4,
            )
        else:
            self.tls_stats = self._run_stubbed_tls(tls_latency)

    def _run_stubbed_tls(self, latencies: dict[int, float]) -> dict[str, int]:
        """Run the TLS stage with one deterministic handshake time per port."""
        original = tls_test.tls_check

        def fake(host, port, sni, timeout, *, insecure=False):  # type: ignore[no-untyped-def]
            ms = latencies.get(port)
            if ms is None:
                return (False, None, "refused")
            return (True, ms, None)

        tls_test.tls_check = fake
        try:
            return tls_test.tls_runner_threaded(
                self.filtered_path, self.tls_path, self.faulty_path,
                timeout=0.5, max_workers=4,
            )
        finally:
            tls_test.tls_check = original

    def tls_link_texts(self) -> list[str]:
        return [row.split("\t", 1)[1] for row in support.read_lines(self.tls_path)]

    def faulty_link_texts(self) -> list[str]:
        return [row.split("\t", 1)[1] for row in support.read_lines(self.faulty_path)]


class ConservationTestCase(support.LoopbackTestCase):
    """Builds an input that exercises every bucket, then audits the result."""

    UNPARSEABLE = [
        "this is not a link at all",
        "<html><head><title>404</title></head></html>",
        "proxy.example:notaport",
        "vless://",
        "   ",
    ]
    #: Ports are injected by :meth:`build`; these are the counts per bucket.
    FAST_LINKS = 5
    SLOW_LINKS = 3
    DEAD_LINKS = 2
    DUPLICATE_LINKS = 3

    def build(self) -> PipelineRun:
        fast_port = self._reserve()
        slow_port = self._reserve()
        dead_port = self._reserve()

        def link(port: int, tag: str) -> str:
            return f"vless://uuid-{tag}@127.0.0.1:{port}#note-{tag}"

        lines: list[str] = []
        for index in range(self.FAST_LINKS):
            lines.append(link(fast_port, f"fast{index}"))
        for index in range(self.SLOW_LINKS):
            lines.append(link(slow_port, f"slow{index}"))
        for index in range(self.DEAD_LINKS):
            lines.append(link(dead_port, f"dead{index}"))
        # Duplicates: same proxy, different fragment, plus an exact repeat.
        lines.append(link(fast_port, "fast0"))
        lines.append(f"{link(fast_port, 'fast0')}#a-different-note")
        lines.append(link(fast_port, "fast0"))
        # Unparseable noise, interspersed.
        for index, junk in enumerate(self.UNPARSEABLE):
            lines.insert(index * 3, junk)

        seed = {
            netprobe.endpoint_str("127.0.0.1", fast_port): FAST_MS,
            netprobe.endpoint_str("127.0.0.1", slow_port): SLOW_MS,
            netprobe.endpoint_str("127.0.0.1", dead_port): None,
        }
        with self.quiet():
            run = PipelineRun(
                self.workdir, lines, seed, LATENCY_THRESHOLD_MS,
                # Every fast link handshakes; the first half of them "fails" on
                # a second, distinct port so both TLS buckets are populated.
                tls_latency=None,
            )
        self.fast_port, self.slow_port, self.dead_port = fast_port, slow_port, dead_port
        return run

    def _reserve(self) -> int:
        """A distinct loopback port per synthetic endpoint."""
        self._next = getattr(self, "_next", 0) + 1
        return 21000 + self._next

    def expected(self) -> dict[str, int]:
        return {
            "total": self.FAST_LINKS + self.SLOW_LINKS + self.DEAD_LINKS
                     + self.DUPLICATE_LINKS + len(self.UNPARSEABLE) - 1,
            "unparseable": len(self.UNPARSEABLE) - 1,
            "duplicates": self.DUPLICATE_LINKS,
            "dead": self.DEAD_LINKS,
            "slow": self.SLOW_LINKS,
            "fast": self.FAST_LINKS,
        }


class LoadAccountingTests(ConservationTestCase):
    """Dedupe + parse accounting: total == unique + duplicates + unparseable."""

    def test_every_input_line_is_accounted_for_at_the_load_stage(self) -> None:
        run = self.build()
        stats = run.load_stats
        self.assertEqual(
            stats.dropped + stats.duplicates + stats.links, stats.total_lines
        )
        expected = self.expected()
        self.assertEqual(stats.duplicates, expected["duplicates"])
        self.assertEqual(stats.dropped, expected["unparseable"])
        self.assertEqual(stats.links, expected["fast"] + expected["slow"] + expected["dead"])
        self.assertEqual(stats.endpoints, 3)

    def test_the_duplicate_links_keep_the_first_seen_spelling(self) -> None:
        run = self.build()
        alive = support.read_lines(run.alive_path)
        self.assertIn(f"vless://uuid-fast0@127.0.0.1:{self.fast_port}#note-fast0", alive)
        self.assertNotIn("#a-different-note", "\n".join(alive))


class BucketIndependenceTests(ConservationTestCase):
    """The four destinations are disjoint and jointly exhaustive."""

    def test_no_link_appears_in_two_buckets(self) -> None:
        run = self.build()
        tls_texts = run.tls_link_texts()
        faulty_texts = run.faulty_link_texts()
        overlap = set(tls_texts) & set(faulty_texts)
        self.assertEqual(overlap, set(), "a link cannot both pass and fail the TLS stage")
        counts = collections.Counter(tls_texts + faulty_texts)
        repeated = {text: n for text, n in counts.items() if n > 1}
        self.assertEqual(repeated, {}, "a link may appear at most once across both outputs")

    def test_tls_outputs_together_are_exactly_the_filtered_input(self) -> None:
        run = self.build()
        filtered = support.read_lines(run.filtered_path)
        produced = run.tls_link_texts() + run.faulty_link_texts()
        self.assertEqual(
            collections.Counter(produced), collections.Counter(filtered),
            "the TLS stage must echo its input exactly once, in or out of success",
        )

    def test_the_tls_stage_counts_balance(self) -> None:
        run = self.build()
        self.assertEqual(
            run.tls_stats["ok"] + run.tls_stats["failed"], run.tls_stats["tested"]
        )
        self.assertEqual(run.tls_stats["tested"], len(support.read_lines(run.filtered_path)))

    def test_parsed_links_split_into_dead_over_threshold_and_tested(self) -> None:
        run = self.build()
        total_parsed = run.load_stats.links
        dead = run.probe_stats["links_dead"]
        over_latency = run.filter_stats["rejected"]
        tested = run.tls_stats["tested"]
        self.assertEqual(dead + over_latency + tested, total_parsed)
        expected = self.expected()
        self.assertEqual(dead, expected["dead"])
        self.assertEqual(over_latency, expected["slow"])
        self.assertEqual(tested, expected["fast"])

    def test_alive_links_are_exactly_the_links_with_a_measurement(self) -> None:
        run = self.build()
        alive = support.read_lines(run.alive_path)
        self.assertEqual(len(alive), self.expected()["fast"] + self.expected()["slow"])
        self.assertTrue(all(f":{self.dead_port}#" not in line for line in alive))

    def test_filtered_output_is_a_subset_of_alive(self) -> None:
        run = self.build()
        alive = support.read_lines(run.alive_path)
        filtered = support.read_lines(run.filtered_path)
        self.assertEqual(set(filtered), set(alive) - set(
            line for line in alive if f":{self.slow_port}#" in line
        ))

    def test_the_full_identity_holds(self) -> None:
        run = self.build()
        total = run.load_stats.total_lines
        buckets = (
            run.load_stats.dropped
            + run.load_stats.duplicates
            + run.probe_stats["links_dead"]
            + run.filter_stats["rejected"]
            + run.tls_stats["tested"]
        )
        self.assertEqual(
            buckets, total,
            "dropped + duplicates + dead + over-latency + tls-tested == input lines",
        )


class StagedTlsOutcomeTests(support.LoopbackTestCase):
    """With a stubbed handshake, both TLS buckets are provably reachable."""

    def test_both_tls_buckets_are_populated_and_disjoint(self) -> None:
        fast_port, slow_port, dead_port = 21101, 21102, 21103
        lines = [
            f"vless://a@127.0.0.1:{fast_port}#a",
            f"vless://b@127.0.0.1:{fast_port}#b",
            f"vless://c@127.0.0.1:{slow_port}#c",
            f"vless://d@127.0.0.1:{dead_port}#d",
        ]
        seed = {
            netprobe.endpoint_str("127.0.0.1", fast_port): FAST_MS,
            netprobe.endpoint_str("127.0.0.1", slow_port): FAST_MS,
            netprobe.endpoint_str("127.0.0.1", dead_port): None,
        }
        with self.quiet():
            run = PipelineRun(
                self.workdir, lines, seed, LATENCY_THRESHOLD_MS,
                # fast port handshakes fine, slow port does not.
                tls_latency={fast_port: 3.5, slow_port: None},
            )
        self.assertEqual(run.tls_stats["tested"], 3)
        self.assertEqual(run.tls_stats["ok"], 2)
        self.assertEqual(run.tls_stats["failed"], 1)
        self.assertEqual(len(run.tls_link_texts()), 2)
        self.assertEqual(len(run.faulty_link_texts()), 1)
        self.assertEqual(set(run.faulty_link_texts()), {lines[2]})
        self.assertEqual(set(run.tls_link_texts()), {lines[0], lines[1]})
        self.assertEqual(run.probe_stats["links_dead"], 1)

    def test_tls_successes_are_written_numerically_sorted(self) -> None:
        ports = [21201, 21202, 21203, 21204]
        lines = [f"vless://p{port}@127.0.0.1:{port}#p{port}" for port in ports]
        seed = {netprobe.endpoint_str("127.0.0.1", port): FAST_MS for port in ports}
        with self.quiet():
            run = PipelineRun(
                self.workdir, lines, seed, 10_000.0,
                # Deliberately not ascending in input order, and not in
                # lexicographic order either (100 > 9 as a string).
                tls_latency={ports[0]: 100.0, ports[1]: 9.0, ports[2]: 10.0,
                             ports[3]: 2.0},
            )
        values = [ms for ms, _text in support.read_scored(run.tls_path)]
        self.assertEqual(values, [2.0, 9.0, 10.0, 100.0])
        self.assertNotEqual(values, sorted(values, key=str))


class DedupeAcrossStagesTests(support.LoopbackTestCase):
    """A duplicated proxy must be probed once and carried once."""

    def test_many_links_over_one_endpoint_are_probed_once(self) -> None:
        port = 21301
        lines = [f"vless://u{index}@127.0.0.1:{port}#n{index}" for index in range(50)]
        lines += [f"vless://u{index}@127.0.0.1:{port}#other-note" for index in range(50)]
        real_probe = netprobe.probe_endpoint
        connects: list[tuple] = []

        def counting(host: str, port_: int, timeout: float):
            connects.append((host, port_))
            return real_probe(host, port_, timeout)

        netprobe.probe_endpoint = counting
        self.addCleanup(setattr, netprobe, "probe_endpoint", real_probe)

        path = support.write_lines(self.path("in.de"), lines)
        with self.quiet():
            stats = netprobe.probe_file(
                path, self.path("out.alive"), self.path("out.timings.jsonl"),
                timeout=0.5, max_workers=4,
            )
        self.assertEqual(stats["links_in"], 50, "the 50 duplicate lines must collapse")
        self.assertEqual(stats["endpoints"], 1)
        self.assertEqual(len(support.read_lines(self.path("out.timings.jsonl"))), 1)


class EmptyAndDegenerateInputTests(support.LoopbackTestCase):
    """Degenerate inputs must still balance, not divide by zero or vanish."""

    def test_an_empty_file_produces_no_buckets_and_no_error(self) -> None:
        path = support.write_lines(self.path("in.txt"), [])
        with self.quiet():
            probe = netprobe.probe_file(
                path, self.path("in.alive"), self.path("in.timings.jsonl"),
                timeout=0.5, max_workers=2,
            )
            filtered = netprobe.filter_by_latency(
                self.path("in.alive"), self.path("in.filtered"),
                self.path("in.timings.jsonl"), max_ms=800.0,
            )
            tls = tls_test.tls_runner_threaded(
                self.path("in.filtered"), self.path("in.tls"), self.path("in.tls_faulty"),
                timeout=0.5, max_workers=2,
            )
        self.assertEqual(probe["links_in"], 0)
        self.assertEqual(filtered, {"links_in": 0, "kept": 0, "rejected": 0, "links_dropped": 0})
        self.assertEqual(tls, {"tested": 0, "ok": 0, "failed": 0})

    def test_a_file_of_pure_junk_is_fully_accounted_as_unparseable(self) -> None:
        junk = ["garbage", "<html/>", "proxy.example:notaport", "!!!", "   "]
        path = support.write_lines(self.path("in.txt"), junk)
        _parsed, stats = links.load_unique_detailed(path)
        self.assertEqual(stats.links, 0)
        self.assertEqual(stats.dropped, len(junk) - 1, "the all-blank line is not a line")
        with self.quiet():
            probe = netprobe.probe_file(
                path, self.path("in.alive"), self.path("in.timings.jsonl"),
                timeout=0.5, max_workers=2,
            )
        self.assertEqual(probe["links_in"], 0)
        self.assertEqual(probe["endpoints"], 0)

    def test_a_single_link_survives_every_stage(self) -> None:
        port = 21401
        line = f"vless://solo@127.0.0.1:{port}#solo"
        seed = {netprobe.endpoint_str("127.0.0.1", port): FAST_MS}
        with self.quiet():
            run = PipelineRun(self.workdir, [line], seed, 10_000.0,
                              tls_latency={port: 1.25})
        self.assertEqual(run.load_stats.links, 1)
        self.assertEqual(run.tls_stats["ok"], 1)
        self.assertEqual(run.tls_link_texts(), [line])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
