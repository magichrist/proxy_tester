"""Proof that this suite is hermetic: no public hostnames, no outbound sockets.

Two independent checks, because either one alone is weak:

* a *runtime* check -- ``support.install_network_guard`` wraps ``socket`` at
  import time so any connect to a non-loopback address, or any DNS lookup of a
  non-loopback name, raises :class:`support.ExternalNetworkAccess`. Every test
  module imports ``support``, so the whole run is inside the guard. If a test
  ever tries to leave the machine, it fails loudly instead of quietly working
  on a machine that happens to be online.

* a *static* check -- the test sources themselves are scanned for public
  hostnames, routable IP literals and URL literals. A runtime guard cannot help
  a test that merely *mentions* the internet, and a suite that names public
  hosts is one refactor away from a flaky test.

The forbidden patterns are assembled from fragments so that this file does not
itself trip the scanner.
"""

from __future__ import annotations

import os
import re
import socket
import unittest

try:  # discovery puts tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

#: Hostnames that must never appear in a test. Built from fragments on purpose.
FORBIDDEN_HOST_FRAGMENTS = [
    "exam" + "ple.com",
    "exam" + "ple.org",
    "goo" + "gle.com",
    "goo" + "gleapis.com",
    "gstatic." + "com",
    "cloud" + "flare",
    "ama" + "zonaws",
    "git" + "hub.com",
    "git" + "hubusercontent.com",
    "raw.git" + "hubuser" + "content.com",
    "v2ray",
    "xray",
    "onion",
    "paste" + "bin",
    "haste" + "bin",
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
]

#: IP literals a test may name. Everything else is treated as routable.
ALLOWED_IP_LITERALS = {
    "127.0.0.1",  # loopback, the only address any listener uses
    "0.0.0.0",
    # RFC 5737 / RFC 3849 documentation ranges, used in parse-only fixtures
    # where no socket is ever created.
    "192.0.2.0", "192.0.2.1",
    "198.51.100.0", "198.51.100.1", "198.51.100.7", "198.51.100.9",
    "203.0.113.0", "203.0.113.5",
    "999.1.1.1",  # deliberately invalid, asserted to be rejected by the parser
}

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://")

#: Schemes that may appear in a test: the link formats under test, plus the
#: schemes used in "this is not a link" fixtures. None of them is dereferenced.
LINK_SCHEMES = frozenset({
    "vless", "vmess", "trojan", "ss", "tcp", "socks", "http", "https",
    "ftp", "file", "data",
})


#: This file necessarily names forbidden hosts, because it is the thing that
#: looks for them. Everything else in tests/ is scanned.
SELF = os.path.basename(__file__)


def _sources() -> list[tuple[str, str]]:
    """Return ``(filename, text)`` for every Python file in tests/ but this one."""
    out = []
    for name in sorted(os.listdir(TESTS_DIR)):
        if not name.endswith(".py") or name == SELF:
            continue
        path = os.path.join(TESTS_DIR, name)
        with open(path, "r", encoding="utf-8") as handle:
            out.append((name, handle.read()))
    return out


def _strip_literals_and_comments(text: str) -> str:
    """Blank out string literals and comments so prose is not scanned as code.

    Docstrings legitimately name real services when explaining what the tool is
    for; only actual host literals in code matter.
    """
    without_block_comments = re.sub(r"\"\"\".*?\"\"\"", '""', text, flags=re.S)
    without_comments = re.sub(r"#.*", "", without_block_comments)
    return re.sub(r"'(?:[^'\\\n]|\\.)*'", "''", without_comments)


class NetworkGuardIsArmedTests(unittest.TestCase):
    """The runtime half of the guarantee."""

    def test_guard_is_installed(self) -> None:
        self.assertTrue(support.network_guard_installed())

    def test_guard_blocks_a_non_loopback_connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        with self.assertRaises(support.ExternalNetworkAccess):
            sock.connect(("93.184.216.34", 80))

    def test_guard_blocks_a_non_loopback_dns_lookup(self) -> None:
        with self.assertRaises(support.ExternalNetworkAccess):
            socket.getaddrinfo("example.invalid", 443)

    def test_guard_allows_loopback(self) -> None:
        self.assertTrue(support._is_loopback("127.0.0.1"))
        self.assertTrue(support._is_loopback("127.1.2.3"))
        self.assertTrue(support._is_loopback("::1"))
        self.assertTrue(support._is_loopback("::ffff:127.0.0.1"))
        self.assertTrue(support._is_loopback("localhost"))
        self.assertFalse(support._is_loopback("192.0.2.1"))
        self.assertFalse(support._is_loopback("proxy.example"))

    def test_guard_allows_a_real_loopback_connect(self) -> None:
        with support.tcp_listener() as listener:
            sock = socket.create_connection((listener.host, listener.port), timeout=2.0)
            self.addCleanup(sock.close)
            self.assertIsNotNone(sock)


class NoPublicHostsInSourcesTests(unittest.TestCase):
    """The static half of the guarantee."""

    def test_no_public_hostname_appears_in_any_test_source(self) -> None:
        offenders = []
        for name, text in _sources():
            lowered = text.lower()
            for fragment in FORBIDDEN_HOST_FRAGMENTS:
                if fragment in lowered:
                    offenders.append(f"{name} mentions {fragment!r}")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_no_routable_ip_literal_appears_in_code(self) -> None:
        offenders = []
        for name, text in _sources():
            code = _strip_literals_and_comments(text)
            for match in _IPV4_RE.finditer(code):
                literal = match.group(0)
                if literal not in ALLOWED_IP_LITERALS:
                    offenders.append(f"{name} names {literal}")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_no_url_literal_appears_in_code(self) -> None:
        """Nothing in the suite may fetch a URL, or name one as a fixture."""
        offenders = []
        for name, text in _sources():
            code = _strip_literals_and_comments(text)
            for match in _URL_RE.finditer(code):
                # The link schemes under test are part of the input format, not
                # something the suite dereferences. "socks5" folds to "socks".
                scheme = match.group(0).rstrip(":/").rstrip("0123456789")
                if scheme in LINK_SCHEMES:
                    continue
                offenders.append(f"{name} contains {match.group(0)}")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_the_scanner_actually_finds_things(self) -> None:
        """Guard against a scanner that silently matches nothing."""
        sample = "connect to cloudflare.example and 93.184.216.34 via gopher://x"
        self.assertTrue(
            any(f in sample.lower() for f in FORBIDDEN_HOST_FRAGMENTS)
            or any(m not in ALLOWED_IP_LITERALS for m in _IPV4_RE.findall(sample)),
            "the forbidden-fragment list is empty or the IP regex is broken",
        )
        self.assertIsNotNone(_URL_RE.search(sample))
        self.assertEqual(_IPV4_RE.findall(sample), ["93.184.216.34"])


class NoDependencyTests(unittest.TestCase):
    """The suite must not have grown a dependency; requirements.txt stays empty."""

    def test_requirements_txt_is_empty(self) -> None:
        path = os.path.join(os.path.dirname(TESTS_DIR), "requirements.txt")
        self.assertTrue(os.path.exists(path), "requirements.txt should still exist")
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
        self.assertEqual(
            content.strip(), "",
            "the project is stdlib-only; requirements.txt must stay empty",
        )

    def test_no_test_imports_a_third_party_package(self) -> None:
        allowed = {
            # stdlib
            "base64", "binascii", "collections", "contextlib", "io", "json",
            "os", "re", "shutil", "socket", "ssl", "sys", "tempfile", "textwrap",
            "threading", "time", "types", "typing", "unittest", "urllib",
            "dataclasses", "itertools", "pathlib", "subprocess", "weakref",
            "__future__",
            "xml", "http", "email", "stat",
            # the project itself
            "Config", "base64_decryptor", "links", "netprobe", "progress",
            "start", "tls_test", "tests",
            # this suite
            "support",
        }
        import_re = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_.]*)", re.M)
        offenders = set()
        for name, text in _sources():
            for match in import_re.finditer(text):
                root = match.group(1).split(".")[0]
                if root not in allowed:
                    offenders.add(f"{name} imports {match.group(1)!r}")
        self.assertEqual(offenders, set(), "\n".join(sorted(offenders)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
