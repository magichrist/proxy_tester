"""Tests for links.py -- the single source of truth for parsing proxy links.

All hosts used here are RFC 2606 / RFC 5737 documentation names and addresses
that cannot resolve or route; nothing in this module opens a socket.
"""

from __future__ import annotations

import base64
import json
import unittest

try:  # discovery puts tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

import links

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
HOST = "edge1.proxy.example"
OTHER = "edge2.proxy.example"

VLESS = f"vless://{UUID}@{HOST}:443?type=ws&security=tls&sni=cdn.proxy.example#Note"
TROJAN = f"trojan://pa%40ss@{HOST}:8443?sni=cdn.proxy.example#TR"
SS_BLOB = base64.b64encode(b"aes-256-gcm:secret@edge3.proxy.example:8388").decode()
SS_WHOLE = f"ss://{SS_BLOB}"
SS_USERINFO = (
    "ss://" + base64.b64encode(b"aes-256-gcm:secret").decode() + "@edge3.proxy.example:8388"
)
VMESS_BODY = json.dumps(
    {
        "v": "2",
        "ps": "n",
        "add": "edge4.proxy.example",
        "port": "443",
        "id": "11111111-2222-3333-4444-555555555555",
        "aid": "0",
        "net": "ws",
        "host": "cdn.proxy.example",
        "path": "/ray",
        "tls": "tls",
        "sni": "cdn.proxy.example",
    }
)
VMESS = "vmess://" + base64.b64encode(VMESS_BODY.encode()).decode()


class ParseVlessTests(unittest.TestCase):
    """A well-formed vless link must yield host, port, sni and uuid."""

    def test_valid_vless_link_parses_host_port_sni_uuid(self) -> None:
        parsed = links.parse_link(VLESS)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.scheme, "vless")
        self.assertEqual(parsed.host, HOST)
        self.assertEqual(parsed.port, 443)
        self.assertEqual(parsed.sni, "cdn.proxy.example")
        self.assertEqual(parsed.uuid, UUID)
        self.assertEqual(parsed.endpoint, (HOST, 443))
        self.assertEqual(parsed.endpoint_str, f"{HOST}:443")
        self.assertEqual(parsed.raw, VLESS)

    def test_sni_falls_back_to_host_query_then_to_url_host(self) -> None:
        from_host = links.parse_link(f"vless://{UUID}@{HOST}:443?host=fallback.example#x")
        assert from_host is not None
        self.assertEqual(from_host.sni, "fallback.example")

        from_url = links.parse_link(f"vless://{UUID}@{HOST}:443#x")
        assert from_url is not None
        self.assertEqual(from_url.sni, HOST)

    def test_explicit_port_is_honoured(self) -> None:
        parsed = links.parse_link(f"vless://{UUID}@{HOST}:2053#x")
        assert parsed is not None
        self.assertEqual(parsed.port, 2053)

    def test_ipv6_literal_in_brackets(self) -> None:
        parsed = links.parse_link(f"vless://{UUID}@[2001:db8::1]:443?sni=a.example#x")
        assert parsed is not None
        self.assertEqual(parsed.host, "2001:db8::1")
        self.assertEqual(parsed.port, 443)
        # endpoint_str re-brackets IPv6 so the cache key is a legal host:port
        # pair and matches netprobe.endpoint_str byte for byte.
        self.assertEqual(parsed.endpoint_str, "[2001:db8::1]:443")


class MissingPortTests(unittest.TestCase):
    """A link with no port is the exact case the old nc_test.sh dropped on the floor."""

    def test_missing_port_defaults_to_443_and_link_survives(self) -> None:
        parsed = links.parse_link(f"vless://{UUID}@{HOST}?security=tls#NoPort")
        self.assertIsNotNone(parsed, "a port-less vless link must not be dropped")
        assert parsed is not None
        self.assertEqual(parsed.port, links.DEFAULT_PORT)
        self.assertEqual(parsed.port, 443)
        self.assertEqual(parsed.endpoint, (HOST, 443))

    def test_missing_port_is_not_dropped_by_the_file_loader(self) -> None:
        with support.workspace() as work:
            path = support.write_lines(
                f"{work}/in.txt",
                [f"vless://{UUID}@{HOST}#NoPort", f"trojan://pw@{HOST}#AlsoNoPort"],
            )
            parsed, dropped = links.load_unique(path)
            self.assertEqual(dropped, 0)
            self.assertEqual([link.port for link in parsed], [443, 443])
            self.assertEqual({link.host for link in parsed}, {HOST})

    def test_bare_host_defaults_to_443(self) -> None:
        parsed = links.parse_link("198.51.100.7")
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.host, "198.51.100.7")
        self.assertEqual(parsed.port, 443)

    def test_vmess_missing_port_defaults_to_443(self) -> None:
        body = json.dumps({"add": "edge4.proxy.example", "id": UUID})
        parsed = links.parse_link("vmess://" + base64.b64encode(body.encode()).decode())
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.port, 443)


class MalformedPortTests(unittest.TestCase):
    """A port that is present but unusable must be rejected, never coerced to 443."""

    def test_bare_host_with_non_numeric_port_is_rejected(self) -> None:
        self.assertIsNone(links.parse_link("proxy.example:notaport"))

    def test_shaped_link_with_non_numeric_port_is_rejected(self) -> None:
        self.assertIsNone(links.parse_link(f"vless://{UUID}@{HOST}:notaport"))
        self.assertIsNone(links.parse_link(f"trojan://pw@{HOST}:https"))

    def test_out_of_range_ports_are_rejected(self) -> None:
        for port in ("0", "65536", "99999", "-1"):
            with self.subTest(port=port):
                self.assertIsNone(links.parse_link(f"vless://{UUID}@{HOST}:{port}"))

    def test_a_malformed_port_line_is_reported_as_dropped_not_coerced(self) -> None:
        with support.workspace() as work:
            path = support.write_lines(
                f"{work}/in.txt",
                [f"vless://{UUID}@{HOST}:notaport", f"vless://{UUID}@{OTHER}:443#ok"],
            )
            parsed, dropped = links.load_unique(path)
            self.assertEqual(dropped, 1)
            self.assertEqual([link.host for link in parsed], [OTHER])

    def test_good_port_still_parses_next_to_a_bad_one(self) -> None:
        self.assertIsNotNone(links.parse_link("proxy.example:8443"))


class SchemeCoverageTests(unittest.TestCase):
    """trojan, both ss spellings, vmess and bare host forms."""

    def test_trojan(self) -> None:
        parsed = links.parse_link(TROJAN)
        assert parsed is not None
        self.assertEqual(parsed.scheme, "trojan")
        self.assertEqual(parsed.host, HOST)
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.uuid, "pa@ss", "userinfo must be percent-decoded")
        self.assertEqual(parsed.sni, "cdn.proxy.example")

    def test_ss_whole_link_base64(self) -> None:
        parsed = links.parse_link(SS_WHOLE)
        assert parsed is not None
        self.assertEqual(parsed.scheme, "ss")
        self.assertEqual(parsed.host, "edge3.proxy.example")
        self.assertEqual(parsed.port, 8388)
        self.assertEqual(parsed.uuid, "aes-256-gcm:secret")

    def test_ss_userinfo_base64(self) -> None:
        parsed = links.parse_link(SS_USERINFO)
        assert parsed is not None
        self.assertEqual(parsed.scheme, "ss")
        self.assertEqual(parsed.host, "edge3.proxy.example")
        self.assertEqual(parsed.port, 8388)
        self.assertEqual(parsed.uuid, "aes-256-gcm:secret")

    def test_both_ss_spellings_share_one_dedupe_key(self) -> None:
        first, second = links.parse_link(SS_WHOLE), links.parse_link(SS_USERINFO)
        assert first is not None and second is not None
        self.assertEqual(first.key, second.key)
        unique, duplicates = links.dedupe([SS_WHOLE, SS_USERINFO])
        self.assertEqual(duplicates, 1)
        self.assertEqual(len(unique), 1)

    def test_vmess_base64_json_body(self) -> None:
        parsed = links.parse_link(VMESS)
        assert parsed is not None
        self.assertEqual(parsed.scheme, "vmess")
        self.assertEqual(parsed.host, "edge4.proxy.example")
        self.assertEqual(parsed.port, 443)
        self.assertEqual(parsed.uuid, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(parsed.sni, "cdn.proxy.example")

    def test_bare_host_and_host_port(self) -> None:
        with_port = links.parse_link("198.51.100.9:8080")
        assert with_port is not None
        self.assertEqual((with_port.host, with_port.port), ("198.51.100.9", 8080))

        without = links.parse_link("198.51.100.9")
        assert without is not None
        self.assertEqual((without.host, without.port), ("198.51.100.9", 443))

    def test_bare_bracketed_ipv6(self) -> None:
        parsed = links.parse_link("[::1]:8080")
        assert parsed is not None
        self.assertEqual((parsed.host, parsed.port), ("::1", 8080))


class HostShapeTests(unittest.TestCase):
    """Hostnames, IPv4 and IPv6 all have to survive parsing."""

    def test_hostname(self) -> None:
        parsed = links.parse_link(f"vless://{UUID}@a.b.proxy.example:2053#x")
        assert parsed is not None
        self.assertEqual(parsed.host, "a.b.proxy.example")

    def test_single_label_hostname_is_rejected(self) -> None:
        self.assertIsNone(links.parse_link("localhost"))

    def test_ipv4(self) -> None:
        parsed = links.parse_link(f"vless://{UUID}@203.0.113.5:8443#x")
        assert parsed is not None
        self.assertEqual((parsed.host, parsed.port), ("203.0.113.5", 8443))

    def test_ipv4_out_of_range_octet_is_rejected(self) -> None:
        self.assertIsNone(links.parse_link("vless://%s@999.1.1.1:443" % UUID))

    def test_ipv6(self) -> None:
        parsed = links.parse_link(f"vless://{UUID}@[2001:db8::dead:beef]:9000#x")
        assert parsed is not None
        self.assertEqual(parsed.host, "2001:db8::dead:beef")
        self.assertEqual(parsed.port, 9000)
        self.assertEqual(parsed.endpoint_str, "[2001:db8::dead:beef]:9000")
    def test_malformed_ipv6_is_rejected(self) -> None:
        self.assertIsNone(links.parse_link(f"vless://{UUID}@[2001:db8::1::2]:443"))

    def test_host_with_whitespace_is_rejected(self) -> None:
        self.assertIsNone(links.parse_link(f"vless://{UUID}@bad host.example:443"))


class DedupeTests(unittest.TestCase):
    """The dedup key decides what "the same proxy" means."""

    def test_fragment_is_ignored_and_first_seen_line_wins(self) -> None:
        first = f"vless://{UUID}@{HOST}:443?type=ws#first-note"
        second = f"vless://{UUID}@{HOST}:443?type=ws#second-note"
        unique, duplicates = links.dedupe([first, second])
        self.assertEqual(duplicates, 1)
        self.assertEqual(unique, [first], "the first-seen raw line must represent the pair")

    def test_query_param_order_does_not_create_distinct_entries(self) -> None:
        a = f"vless://{UUID}@{HOST}:443?alpha=1&beta=2#note"
        b = f"vless://{UUID}@{HOST}:443?beta=2&alpha=1#other-note"
        parsed_a, parsed_b = links.parse_link(a), links.parse_link(b)
        assert parsed_a is not None and parsed_b is not None
        self.assertNotEqual(a.split("#")[0], b.split("#")[0])
        self.assertEqual(parsed_a.key, parsed_b.key)
        unique, duplicates = links.dedupe([a, b])
        self.assertEqual((len(unique), duplicates), (1, 1))

    def test_different_query_values_do_stay_distinct(self) -> None:
        a = f"vless://{UUID}@{HOST}:443?security=tls#n"
        b = f"vless://{UUID}@{HOST}:443?security=none#n"
        unique, duplicates = links.dedupe([a, b])
        self.assertEqual((len(unique), duplicates), (2, 0))

    def test_dedupe_ignores_blank_and_non_string_lines(self) -> None:
        junk: list = ["", "   ", VLESS, None, 42, VLESS]
        unique, duplicates = links.dedupe(junk)
        self.assertEqual(unique, [VLESS])
        self.assertEqual(duplicates, 1)

    def test_dedupe_collapses_unparseable_junk_instead_of_multiplying(self) -> None:
        unique, duplicates = links.dedupe(["<<<not a link>>>", "<<<not a link>>>"])
        self.assertEqual((len(unique), duplicates), (1, 1))


class IterRawLinesTests(support.LoopbackTestCase):
    """Reading a link file must survive whatever a download actually contains."""

    def test_tolerates_crlf_blank_lines_and_undecodable_bytes(self) -> None:
        path = self.path("messy.txt")
        with open(path, "wb") as handle:
            handle.write(b"first\r\n")
            handle.write(b"\r\n")
            handle.write(b"   \n")
            handle.write(b"second\n")
            handle.write(b"third\xff\xfe-binary\n")
            handle.write(b"\n")
        lines = list(links.iter_raw_lines(path))
        self.assertEqual(len(lines), 3)
        self.assertNotIn("\r", "".join(lines))
        self.assertTrue(lines[0].startswith("first"))
        self.assertTrue(lines[1].startswith("second"))
        self.assertTrue(lines[2].startswith("third"))
        self.assertIn("\ufffd", lines[2], "an undecodable byte must not abort the read")

    def test_missing_file_propagates(self) -> None:
        with self.assertRaises(OSError):
            list(links.iter_raw_lines(self.path("absent.txt")))


class LoadAccountingTests(support.LoopbackTestCase):
    """Dropped and duplicate counts are what make silent loss reportable."""

    LINES = [
        f"vless://{UUID}@{HOST}:443#one",
        f"vless://{UUID}@{HOST}:443#two",
        f"vless://{UUID}@{OTHER}:443#three",
        "not a link at all",
        "proxy.example:notaport",
    ]

    def test_load_unique_returns_links_and_dropped(self) -> None:
        path = support.write_lines(self.path("in.txt"), self.LINES)
        parsed, dropped = links.load_unique(path)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(dropped, 2)

    def test_load_unique_detailed_reports_dropped_and_duplicates(self) -> None:
        path = support.write_lines(self.path("in.txt"), self.LINES)
        parsed, stats = links.load_unique_detailed(path)
        self.assertIsInstance(stats, links.LoadStats)
        self.assertEqual(stats.total_lines, 5)
        self.assertEqual(stats.parsed_lines, 3)
        self.assertEqual(stats.dropped, 2)
        self.assertEqual(stats.duplicates, 1)
        self.assertEqual(stats.links, len(parsed))
        self.assertEqual(stats.endpoints, 2)
        self.assertEqual(stats.dropped + stats.duplicates + stats.links, stats.total_lines)

    def test_duplicate_lines_are_collapsed_not_counted_as_dropped(self) -> None:
        path = support.write_lines(self.path("in.txt"), [VLESS, VLESS, VLESS])
        _parsed, stats = links.load_unique_detailed(path)
        self.assertEqual(stats.dropped, 0)
        self.assertEqual(stats.duplicates, 2)
        self.assertEqual(stats.links, 1)


class FilterLatencyTests(unittest.TestCase):
    """filter_latency is the only gate between 'alive' and 'TLS'."""

    def _links(self) -> list[links.ParsedLink]:
        out = []
        for index, host in enumerate((HOST, OTHER, "edge5.proxy.example")):
            parsed = links.parse_link(f"vless://{UUID}-{index}@{host}:443#n{index}")
            assert parsed is not None
            out.append(parsed)
        return out

    def test_unmeasured_endpoints_are_rejected(self) -> None:
        parsed = self._links()
        timings = {parsed[0].endpoint_str: 10.0}
        within, rejected = links.filter_latency(parsed, timings, 800.0)
        self.assertEqual([link.raw for link in within], [parsed[0].raw])
        self.assertEqual(
            [link.raw for link in rejected], [parsed[1].raw, parsed[2].raw],
            "an endpoint missing from timings failed the probe and must be rejected",
        )

    def test_none_valued_timings_are_rejected(self) -> None:
        parsed = self._links()
        timings = {link.endpoint_str: None for link in parsed}
        within, rejected = links.filter_latency(parsed, timings, 800.0)
        self.assertEqual(within, [])
        self.assertEqual(len(rejected), 3)

    def test_sorted_ascending_by_ms(self) -> None:
        parsed = self._links()
        timings = {
            parsed[0].endpoint_str: 500.0,
            parsed[1].endpoint_str: 1.25,
            parsed[2].endpoint_str: 90.0,
        }
        within, _rejected = links.filter_latency(parsed, timings, 800.0)
        self.assertEqual([link.endpoint_str for link in within],
                         [parsed[1].endpoint_str, parsed[2].endpoint_str, parsed[0].endpoint_str])

    def test_threshold_is_inclusive(self) -> None:
        parsed = self._links()
        timings = {link.endpoint_str: 800.0 for link in parsed}
        within, rejected = links.filter_latency(parsed, timings, 800.0)
        self.assertEqual(len(within), 3)
        self.assertEqual(rejected, [])

    def test_sort_is_stable_for_equal_timings(self) -> None:
        parsed = self._links()
        timings = {link.endpoint_str: 7.5 for link in parsed}
        within, _ = links.filter_latency(parsed, timings, 800.0)
        self.assertEqual([link.raw for link in within], [link.raw for link in parsed])

    def test_rejected_keeps_input_order(self) -> None:
        parsed = self._links()
        timings = {parsed[0].endpoint_str: 5.0, parsed[1].endpoint_str: 9000.0}
        _within, rejected = links.filter_latency(parsed, timings, 800.0)
        self.assertEqual([link.raw for link in rejected], [parsed[1].raw, parsed[2].raw])


class RobustnessTests(unittest.TestCase):
    """parse_link must never raise, whatever the subscription server served."""

    JUNK = [
        "", "   ", "\x00", "://", "://@", "http://", "vless://", "vless://@",
        "ss://@@@@", "vmess://{}", "vmess://" + base64.b64encode(b"not json").decode(),
        "trojan://pw@", "vless://u@", "#" * 50, "?" * 50, "a" * 5000,
        "vless://u@host:443?a=%ZZ", "\t\t", "'quoted'", "a, b, c",
        "ftp://u@host:21", "socks5://u@host:1080", "://x", "198.51.100.1:", "[::1]",
    ]

    def test_never_raises_on_junk(self) -> None:
        for line in self.JUNK:
            with self.subTest(line=line[:30]):
                try:
                    result = links.parse_link(line)
                except Exception as exc:  # pragma: no cover - the bug we guard
                    self.fail(f"parse_link({line!r}) raised {type(exc).__name__}: {exc}")
                self.assertTrue(result is None or isinstance(result, links.ParsedLink))

    def test_non_string_input_returns_none(self) -> None:
        for value in (None, 42, b"vless://u@host:443", ["x"]):
            with self.subTest(value=repr(value)):
                self.assertIsNone(links.parse_link(value))  # type: ignore[arg-type]

    def test_scored_artifact_line_reparses(self) -> None:
        """A line read back out of a '<ms>\\t<link>' artifact must still parse."""
        scored = f"42.31\t{VLESS}"
        parsed = links.parse_link(scored)
        self.assertIsNotNone(parsed, "links.py must be able to eat its own output")
        assert parsed is not None
        self.assertEqual(parsed.endpoint_str, f"{HOST}:443")
        # raw is the *normalised* link: the leading ms field is consumed by the
        # parser rather than carried through into the next artifact.
        self.assertEqual(parsed.raw, VLESS)

    def test_scored_artifact_line_is_normalised_by_the_file_loader(self) -> None:
        with support.workspace() as work:
            path = support.write_lines(f"{work}/in.txt", [f"42.31\t{VLESS}"])
            parsed, dropped = links.load_unique(path)
            self.assertEqual(dropped, 0)
            self.assertEqual([link.raw for link in parsed], [VLESS])

    def test_quotes_and_trailing_comma_are_tolerated(self) -> None:
        parsed = links.parse_link(f'"{VLESS}",')
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.host, HOST)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
