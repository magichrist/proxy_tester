"""Tests for Config.py -- the public configuration surface.

``from Config import *`` is documented public API that old code and the README
both rely on, so the legacy names are asserted to keep resolving. The rest of
the module is about :func:`Config.apply_overrides`: it must coerce, validate and
reject atomically.
"""

from __future__ import annotations

import unittest

try:  # discovery puts tests/ on sys.path; a package import also works
    import support
except ImportError:  # pragma: no cover
    from tests import support  # type: ignore[no-redef]

import Config

#: The eight names the pre-refactor README documented. They are public API.
LEGACY_NAMES = (
    "PING_MAX_TIME_MS",
    "PING_COUNT",
    "PING_TIMEOUT",
    "PING_THREADS",
    "NC_TIMEOUT",
    "NC_JOBS",
    "TLS_TIMEOUT",
    "TLS_THREADS",
)

#: The canonical names added by the refactor.
CANONICAL_NAMES = ("MAX_LATENCY_MS", "PROBE_TIMEOUT", "PROBE_WORKERS", "TOP_N")

ALL_NAMES = LEGACY_NAMES + CANONICAL_NAMES


class ConfigGuard(support.LoopbackTestCase):
    """Restores every Config constant after each test in the class."""

    def setUp(self) -> None:
        super().setUp()
        self._snapshot = {name: getattr(Config, name) for name in ALL_NAMES}
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        for name, value in self._snapshot.items():
            setattr(Config, name, value)


class StarImportTests(unittest.TestCase):
    """Correctness requirement 5: the legacy access patterns keep working."""

    def test_star_import_resolves_every_legacy_name(self) -> None:
        namespace: dict[str, object] = {}
        exec("from Config import *", namespace)  # noqa: S102 - the thing under test
        for name in LEGACY_NAMES:
            with self.subTest(name=name):
                self.assertIn(name, namespace, f"Config.{name} no longer resolves")
                self.assertIsInstance(namespace[name], (int, float))

    def test_star_import_resolves_every_canonical_name(self) -> None:
        namespace: dict[str, object] = {}
        exec("from Config import *", namespace)  # noqa: S102
        for name in CANONICAL_NAMES:
            with self.subTest(name=name):
                self.assertIn(name, namespace)
                self.assertIsInstance(namespace[name], (int, float))

    def test_attribute_access_still_works(self) -> None:
        for name in ALL_NAMES:
            with self.subTest(name=name):
                self.assertIsInstance(getattr(Config, name), (int, float))

    def test_defaults_are_documented_in_the_module(self) -> None:
        """PING_TIMEOUT is now unambiguously SECONDS, and the value says so."""
        self.assertEqual(Config.PING_MAX_TIME_MS, 800.0)
        self.assertEqual(Config.PING_COUNT, 1)
        self.assertEqual(Config.PING_TIMEOUT, 1.0)
        self.assertEqual(Config.NC_TIMEOUT, 1.0)
        self.assertEqual(Config.TLS_TIMEOUT, 3.0)
        self.assertEqual(Config.TOP_N, 20)
        self.assertEqual(Config.MAX_LATENCY_MS, Config.PING_MAX_TIME_MS)
        self.assertEqual(Config.PROBE_TIMEOUT, Config.NC_TIMEOUT)
        self.assertEqual(Config.PROBE_WORKERS, Config.NC_JOBS)

    def test_defaults_snapshot_matches_the_live_constants(self) -> None:
        for name, value in Config.DEFAULTS.items():
            with self.subTest(name=name):
                self.assertIn(name, ALL_NAMES)
                self.assertIsInstance(value, (int, float))


class ApplyOverridesTests(ConfigGuard):
    """Type coercion, rejection and alias synchronisation."""

    def test_coerces_strings_to_the_declared_type(self) -> None:
        Config.apply_overrides(["MAX_LATENCY_MS=400", "TLS_THREADS=8", "TOP_N=5"])
        self.assertEqual(Config.MAX_LATENCY_MS, 400.0)
        self.assertIsInstance(Config.MAX_LATENCY_MS, float)
        self.assertEqual(Config.TLS_THREADS, 8)
        self.assertIsInstance(Config.TLS_THREADS, int)
        self.assertEqual(Config.TOP_N, 5)

    def test_accepts_surrounding_whitespace(self) -> None:
        Config.apply_overrides(["  MAX_LATENCY_MS = 250  "])
        self.assertEqual(Config.MAX_LATENCY_MS, 250.0)

    def test_rejects_an_unknown_name(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            Config.apply_overrides(["NOT_A_SETTING=1"])
        self.assertIn("unknown setting", str(ctx.exception))

    def test_rejects_an_unparseable_value(self) -> None:
        for pair in ("MAX_LATENCY_MS=abc", "TLS_THREADS=x", "TOP_N=1.2.3", "MAX_LATENCY_MS="):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    Config.apply_overrides([pair])

    def test_rejects_a_value_below_the_minimum(self) -> None:
        for pair in ("TLS_THREADS=0", "NC_JOBS=0", "PING_THREADS=-1", "PROBE_WORKERS=0"):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    Config.apply_overrides([pair])

    def test_rejects_a_pair_without_an_equals_sign(self) -> None:
        for pair in ("MAX_LATENCY_MS", "", "=400", "MAX_LATENCY_MS=400=500"):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    Config.apply_overrides([pair])

    def test_rejects_a_float_for_an_integer_setting(self) -> None:
        with self.assertRaises(ValueError):
            Config.apply_overrides(["NC_JOBS=2.5"])

    def test_rejects_a_bool_spelled_as_text(self) -> None:
        with self.assertRaises(ValueError):
            Config.apply_overrides(["MAX_LATENCY_MS=True"])

    def test_alias_pair_syncs_from_the_legacy_name(self) -> None:
        Config.apply_overrides(["NC_TIMEOUT=2.5"])
        self.assertEqual(Config.NC_TIMEOUT, 2.5)
        self.assertEqual(Config.PROBE_TIMEOUT, 2.5)

    def test_alias_pair_syncs_from_the_canonical_name(self) -> None:
        Config.apply_overrides(["PROBE_TIMEOUT=3.5"])
        self.assertEqual(Config.PROBE_TIMEOUT, 3.5)
        self.assertEqual(Config.NC_TIMEOUT, 3.5, "the legacy name must follow the canonical one")

    def test_latency_alias_syncs_both_ways(self) -> None:
        Config.apply_overrides(["PING_MAX_TIME_MS=123"])
        self.assertEqual(Config.MAX_LATENCY_MS, 123.0)
        Config.apply_overrides(["MAX_LATENCY_MS=456"])
        self.assertEqual(Config.PING_MAX_TIME_MS, 456.0)

    def test_worker_alias_syncs_both_ways(self) -> None:
        Config.apply_overrides(["NC_JOBS=7"])
        self.assertEqual(Config.PROBE_WORKERS, 7)
        Config.apply_overrides(["PROBE_WORKERS=9"])
        self.assertEqual(Config.NC_JOBS, 9)

    def test_unaliased_names_do_not_disturb_their_neighbours(self) -> None:
        before = (Config.MAX_LATENCY_MS, Config.PING_MAX_TIME_MS,
                  Config.PROBE_TIMEOUT, Config.NC_TIMEOUT)
        Config.apply_overrides(["TLS_TIMEOUT=9.0", "TOP_N=1"])
        self.assertEqual(
            (Config.MAX_LATENCY_MS, Config.PING_MAX_TIME_MS,
             Config.PROBE_TIMEOUT, Config.NC_TIMEOUT),
            before,
        )

    def test_an_invalid_batch_leaves_config_unchanged(self) -> None:
        """All-or-nothing: a rejected batch must not apply its valid prefix."""
        before = {name: getattr(Config, name) for name in ALL_NAMES}
        for batch in (
            ["MAX_LATENCY_MS=400", "NOPE=1"],
            ["TLS_THREADS=8", "MAX_LATENCY_MS=abc"],
            ["TOP_N=3", "TLS_THREADS=0"],
            ["NC_JOBS=4", "GARBAGE"],
        ):
            with self.subTest(batch=batch):
                with self.assertRaises(ValueError):
                    Config.apply_overrides(batch)
                after = {name: getattr(Config, name) for name in ALL_NAMES}
                self.assertEqual(after, before)

    def test_empty_batch_is_a_no_op(self) -> None:
        before = {name: getattr(Config, name) for name in ALL_NAMES}
        Config.apply_overrides([])
        self.assertEqual({name: getattr(Config, name) for name in ALL_NAMES}, before)


class DescribeTests(ConfigGuard):
    """describe() feeds the startup banner and must render every setting."""

    def test_lists_every_setting(self) -> None:
        Config.apply_overrides(["MAX_LATENCY_MS=321"])
        text = Config.describe()
        for name in ALL_NAMES:
            with self.subTest(name=name):
                self.assertIn(name, text)
        self.assertIn("Config (active)", text)
        self.assertIn("overridden", text)
        self.assertIn("321", text)

    def test_shows_the_configured_units(self) -> None:
        text = Config.describe()
        for name in ("PING_MAX_TIME_MS", "MAX_LATENCY_MS"):
            self.assertRegex(text, rf"{name}\s*=.*\bms\b")
        for name in ("PING_TIMEOUT", "NC_TIMEOUT", "PROBE_TIMEOUT", "TLS_TIMEOUT"):
            self.assertRegex(text, rf"{name}\s*=.*\bs\b")

    def test_marks_alias_relationships(self) -> None:
        text = Config.describe()
        self.assertIn("= PING_MAX_TIME_MS", text)
        self.assertIn("= NC_TIMEOUT", text)
        self.assertIn("= NC_JOBS", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
