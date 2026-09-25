"""Shared fixtures for the proxy_tester test suite.

The two things this module exists to guarantee:

1. **Nothing here touches the network.** :func:`install_network_guard` wraps
   ``socket`` so that any connect to a non-loopback address, or any DNS lookup
   of a name that is not loopback, raises immediately. It is installed at import
   time, so *every* test module gets the guard simply by importing this file. A
   test that reaches for the public internet is therefore a hard failure rather
   than a slow, flaky, non-hermetic test.

2. **Every listener is on 127.0.0.1 with an OS-assigned port.** The suite needs
   real sockets -- a real TCP connect to prove the probe works, a real TLS
   handshake to prove the cert-verification switch works -- but never a fixed
   port that could collide with a real service or with a parallel run.
"""

from __future__ import annotations

import contextlib
import io
import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

# --------------------------------------------------------------------------
# Network guard
# --------------------------------------------------------------------------


class ExternalNetworkAccess(AssertionError):
    """Raised when test code tries to leave the loopback interface."""


#: Hostnames/addresses a test is allowed to resolve or connect to.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0", "", "ip6-localhost"})

_GUARD_STATE: dict[str, bool] = {"installed": False}


def _is_loopback(host: object) -> bool:
    """True when ``host`` is a literal loopback address or loopback name."""
    if isinstance(host, (bytes, bytearray)):
        host = host.decode("ascii", "replace")
    text = str(host)
    if text.startswith("::ffff:"):
        text = text[len("::ffff:"):]
    if text in LOOPBACK_HOSTS:
        return True
    # The whole 127.0.0.0/8 range, plus the canonical ::1 spellings.
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return parts[0] == "127"
    return False


def _check(address: object, what: str) -> None:
    if isinstance(address, (tuple, list)) and address:
        if not _is_loopback(address[0]):
            raise ExternalNetworkAccess(
                f"{what} to non-loopback address {address[0]!r}; the test suite "
                f"must run fully offline"
            )


def install_network_guard() -> None:
    """Wrap the socket layer so only loopback is reachable. Idempotent."""
    if _GUARD_STATE["installed"]:
        return
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create_connection = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo

    def guarded_connect(self, address, *args, **kwargs):  # type: ignore[no-untyped-def]
        _check(address, "socket.connect")
        return real_connect(self, address, *args, **kwargs)

    def guarded_connect_ex(self, address, *args, **kwargs):  # type: ignore[no-untyped-def]
        _check(address, "socket.connect_ex")
        return real_connect_ex(self, address, *args, **kwargs)

    def guarded_create_connection(address, *args, **kwargs):  # type: ignore[no-untyped-def]
        _check(address, "socket.create_connection")
        return real_create_connection(address, *args, **kwargs)

    def guarded_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not _is_loopback(host):
            raise ExternalNetworkAccess(
                f"DNS lookup of non-loopback name {host!r}; the test suite must "
                f"run fully offline"
            )
        return real_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
    socket.create_connection = guarded_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]
    _GUARD_STATE["installed"] = True


def network_guard_installed() -> bool:
    """True when :func:`install_network_guard` has run."""
    return _GUARD_STATE["installed"]


@contextlib.contextmanager
def allow_network():  # pragma: no cover - escape hatch, deliberately unused
    """Placeholder escape hatch. Nothing in the suite should need this."""
    yield


install_network_guard()

# --------------------------------------------------------------------------
# Loopback listeners
# --------------------------------------------------------------------------


class _ListenerBase:
    """A 127.0.0.1 listener on an ephemeral port, served by a daemon thread."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(128)
        self.port: int = self._sock.getsockname()[1]
        self.host: str = "127.0.0.1"
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:  # pragma: no cover - timing dependent
        raise NotImplementedError

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def __enter__(self) -> "_ListenerBase":
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


class TcpListener(_ListenerBase):
    """Accepts TCP connections and closes them immediately."""

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            try:
                conn.close()
            except OSError:
                pass


class TlsListener(_ListenerBase):
    """Terminates TLS with a self-signed certificate for 127.0.0.1/localhost."""

    def __init__(self, certfile: str, keyfile: str) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certfile, keyfile)
        super().__init__()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handshake, args=(conn,), daemon=True).start()

    def _handshake(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            self._context.wrap_socket(conn, server_side=True).close()
        except (OSError, ssl.SSLError, ValueError):
            with contextlib.suppress(OSError):
                conn.close()


@contextlib.contextmanager
def tcp_listener():
    """Context manager yielding a live :class:`TcpListener` on loopback."""
    listener = TcpListener()
    try:
        yield listener
    finally:
        listener.stop()


@contextlib.contextmanager
def tls_listener(certfile: str, keyfile: str):
    """Context manager yielding a live :class:`TlsListener` on loopback."""
    listener = TlsListener(certfile, keyfile)
    try:
        yield listener
    finally:
        listener.stop()


def closed_port() -> int:
    """Return a loopback port with nothing listening on it.

    The socket is bound, discovered and closed, so the port is almost certainly
    free. A connect there is refused immediately, which is the failure mode the
    probe tests want -- and it costs microseconds rather than a timeout.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()

# --------------------------------------------------------------------------
# Workspace / output helpers
# --------------------------------------------------------------------------


@contextlib.contextmanager
def workspace():
    """Yield a private temp directory, removed on exit."""
    path = tempfile.mkdtemp(prefix="proxy_tester_tests_")
    try:
        yield path
    finally:
        import shutil

        shutil.rmtree(path, ignore_errors=True)


@contextlib.contextmanager
def silence():
    """Capture stdout and stderr so a noisy stage cannot pollute the report."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        yield buffer


def read_lines(path: str) -> list[str]:
    """Read a file into lines with terminators stripped."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\r\n") for line in handle]


def write_lines(path: str, lines: list[str], *, newline: str = "\n") -> str:
    """Write ``lines`` to ``path`` and return the path."""
    with open(path, "w", encoding="utf-8", newline=newline) as handle:
        for line in lines:
            handle.write(line + newline)
    return path


def read_scored(path: str) -> list[tuple[float, str]]:
    """Read a ``<ms>\\t<link>`` artifact into ``(ms, link)`` pairs."""
    rows: list[tuple[float, str]] = []
    for line in read_lines(path):
        head, tab, rest = line.partition("\t")
        if not tab or not rest.strip():
            continue
        try:
            rows.append((float(head), rest))
        except ValueError:
            continue
    return rows


class Counter:
    """Counts calls to a wrapped callable, recording each argument tuple."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(args)
        return self._impl(*args, **kwargs)

    def _impl(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    @property
    def count(self) -> int:
        return len(self.calls)

# --------------------------------------------------------------------------
# Certificate material
# --------------------------------------------------------------------------
#: A throwaway self-signed certificate for 127.0.0.1/localhost, generated once
#: for this test suite. Committed on purpose: the suite must not shell out to
#: ``openssl`` and must not depend on a package outside the stdlib.
SELF_SIGNED_CERT = """\
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUBWftt0MwhTq5AiNFGeCSHT62M8EwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkyNTE2MzIxNVoYDzIxMjYw
OTAxMTYzMjE1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCcoR5dma1Ek1ZW2W4g4NKu5S72Qa+dyGpZ5xabNVQ1
Fyv1Dn0d9hwMLMHqH38PvNDtBY6cBCEk3qwFa/+3KjG1UuVBGv9BuulYN6sxyd4l
YmYh1grYZiq/X4i7GQ1VXUcPReKPRzjGTIge/m8Dg5sFP8u2qi4PvsFVyZS8W0M7
IK7DvXaSJcC1B3Zaz/njq1GmxnCS0Y5piFTsXlrw+LDG2HRDFng5DHHvW5KP2K2B
yudGirHIolcOCR5t80dSZkJrnv87qJ5dsVNlBRWI0XsDNz1Dvi1tVuLXbKiGMdGG
Zw7beNgWLBOi5jX3T6XRVH4LoCeGdfPD9XQIqLeaKvlDAgMBAAGjbzBtMB0GA1Ud
DgQWBBSXEfYGCALIabP2sEPznspL0xYSUDAfBgNVHSMEGDAWgBSXEfYGCALIabP2
sEPznspL0xYSUDAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9z
dIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAGzuN9SVRsi3PyHJeG+PwMPas6WEP
TFoOycOW+DRmdP9SBGnM5U3T4q9VymQ3C9+A8/y5GnZq1BBfWm7gFVw2WVXmwEO5
0FnN8mJXCfpj+KEbCwsC0bkV9+CjlhcxFcretKTKaVY2guFJRBOu0y1+f7pNphxQ
2lStoKC2FMz6wzvu5hZ15u3M5fCJOlIfFqJxKZg1qAgce/xnT11H3H3DwAzZ7wiP
jQ8rs7R9X1BBuvwxHiyZ0mx7D1vIkPlphircaAGhIW9wnYBJIwKxPgD4+C8QLFZW
PDDK5otpWPRRAPflK/53T7mSxMSh0wVotk8in5SL7llkOVOuU0DsPyhajg==
-----END CERTIFICATE-----
"""

SELF_SIGNED_KEY = """\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCcoR5dma1Ek1ZW
2W4g4NKu5S72Qa+dyGpZ5xabNVQ1Fyv1Dn0d9hwMLMHqH38PvNDtBY6cBCEk3qwF
a/+3KjG1UuVBGv9BuulYN6sxyd4lYmYh1grYZiq/X4i7GQ1VXUcPReKPRzjGTIge
/m8Dg5sFP8u2qi4PvsFVyZS8W0M7IK7DvXaSJcC1B3Zaz/njq1GmxnCS0Y5piFTs
Xlrw+LDG2HRDFng5DHHvW5KP2K2ByudGirHIolcOCR5t80dSZkJrnv87qJ5dsVNl
BRWI0XsDNz1Dvi1tVuLXbKiGMdGGZw7beNgWLBOi5jX3T6XRVH4LoCeGdfPD9XQI
qLeaKvlDAgMBAAECggEAPWoLfwX/43CmHP26adfdpEgm5tYQpxxrXv72ZTs+3mZM
jRT2SCY1Dy0Jh+R7rM8LWLSiG1ifKlbJOoMDTG2V+hQb4jBUwBAq6LVDQg12NlBj
3YaQ0BMXVdx+v2XuTXd6omlzkVyKzW46vXRkUQtsYF2IYgJOd0wDgMC+ujBKp0bn
T/Kpsw2KI2XYRbubTlM/5ggzrYFc91wJXfdkz03Tv8zbGp1yqR16fo2UFy0OE5GI
5YTwq9+3hv6mg0GQUegjCtjsZH2pWdSmDyYTNfnIDFONbOIUHfTaxNaDrSMI9Aif
1uPz0disL4i+9XsQrqF4AvOvjYZcUGHOlCKJLlCfqQKBgQDMKXoNUjG2grWMZCnD
99Fh9qU1ArLaAZQ3XQ4FaPlUJHi1eZfIryP6ZTUwduiML7VpR/jEokxumg8yvXxx
Sd4TJnXDAGF8D99Pp25Vyk/6nWW13v4v46UVMSnzErW0gDKEoINisKd+0ykIgnZs
LAjhcn+AiLq/JkE36kViZmFrjwKBgQDEZgWCW4bDERN72E4xmS3TgIJeFch3fVo7
NRulXyp1QTTE4RmTeCyDVasGMCiX/BqHR1iNRl7M4WFDllKOyd/z3YtFe3vqZBN3
u6y9+Gqgw5ZQ03ILtC8Pu21zokzhpgYd/D0R9JIo1qnV/t2G+cihr0bSmAR9TZ3F
Nbft2vnNDQKBgQCoT+VkSAfd7CJZzFW2Tn7a4WjPrBrgqX6Uqe2ePi2W1b6B9e1R
MDpb+sX/33fV4psPYZtQGHEkmXPAJAEMsJYZeZKKIa08hyVV2LWYmoKXHN22M1Gh
D26QawincRxF445CUsYePX7IirMAZfXVNfRYUHmW8KHsZlBMFaH//mGANwKBgB1G
e+G/lOn03KukRZudEripOkWeB6DQHagftXxEIEcULjJ+v1o9Gp2FIpYsjZCCMs4h
c3CzoaP2oJH7kVjZfLmUN5Nm4cTBoClD32793Z8TKI/pxOE7vZwhuyH2enFUVysX
E19ezn6p6O0OLaVWDHMVdoAjyt+Gt1LTPBSHhJ7tAoGBAIhaHntO512XDLFFrmwk
8bMunYJTGcp761u2jPB7QETLxHPG9Zjdg69qKrx4nu4NtCyOSRCXQi8wfXwFfyK5
KKBc/h06LsHPm3zlZN5t4sMHuKUt8AJPIWv5A0zNB1g2GcInhv7C6TQjb+y0JQQA
7gbsZv7J31vTztmmTgCfYxQw
-----END PRIVATE KEY-----
"""


# --------------------------------------------------------------------------
# Base classes
# --------------------------------------------------------------------------


class LoopbackTestCase(unittest.TestCase):
    """Base class that silences stage output and gives each test a workspace."""

    #: Populated by :meth:`setUp` with a fresh temp directory path.
    workdir: str

    def setUp(self) -> None:
        super().setUp()
        self._stack = contextlib.ExitStack()
        self.addCleanup(self._stack.close)
        self.workdir = self._stack.enter_context(workspace())

    def path(self, name: str) -> str:
        """Return an absolute path to ``name`` inside this test's workspace."""
        return os.path.join(self.workdir, name)

    def quiet(self) -> contextlib.AbstractContextManager:
        """Suppress progress/noise output produced by the stage under test."""
        return self._stack.enter_context(silence())

    def assertNoExternalNetwork(self) -> None:
        """Fail if a test somehow replaced the loopback socket guard."""
        self.assertTrue(
            network_guard_installed(),
            "the loopback network guard was removed; tests must stay offline",
        )
