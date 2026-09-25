"""Runtime configuration for proxy_tester.

Every value is a plain module-level constant so that both historic access
patterns keep working::

    from Config import *          # legacy style, still supported
    import Config; Config.NC_TIMEOUT

Use :func:`apply_overrides` to change values at runtime (the CLI exposes it as
``--set NAME=VALUE``) and :func:`describe` to render the active configuration
for the startup banner.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # keeps the typing name out of `from Config import *`
    from typing import Iterable

# --------------------------------------------------------------------------
# Legacy constant names. These are the documented public API; do not rename.
# --------------------------------------------------------------------------

PING_MAX_TIME_MS = 800.0
PING_COUNT = 1
PING_TIMEOUT = 1.0
PING_THREADS = 30

NC_TIMEOUT = 1.0
NC_JOBS = 30

TLS_TIMEOUT = 3.0
TLS_THREADS = 30

# --------------------------------------------------------------------------
# Canonical names. Derived from the legacy names so the two can never drift.
# --------------------------------------------------------------------------

MAX_LATENCY_MS = float(PING_MAX_TIME_MS)
PROBE_TIMEOUT = float(NC_TIMEOUT)
PROBE_WORKERS = int(NC_JOBS)

TOP_N = 20

# canonical alias -> the legacy constant it mirrors
_ALIAS_SOURCES: dict[str, str] = {
    "MAX_LATENCY_MS": "PING_MAX_TIME_MS",
    "PROBE_TIMEOUT": "NC_TIMEOUT",
    "PROBE_WORKERS": "NC_JOBS",
}

_FLOAT_NAMES = frozenset({
    "PING_MAX_TIME_MS", "PING_TIMEOUT", "NC_TIMEOUT", "TLS_TIMEOUT",
    "MAX_LATENCY_MS", "PROBE_TIMEOUT",
})
_INT_NAMES = frozenset({
    "PING_COUNT", "PING_THREADS", "NC_JOBS", "TLS_THREADS",
    "PROBE_WORKERS", "TOP_N",
})
#: Minimum accepted value per name. None means "any value is fine".
_MINIMUMS: dict[str, float] = {
    "PING_MAX_TIME_MS": 0.0, "PING_COUNT": 0, "PING_TIMEOUT": 0.0,
    "PING_THREADS": 1, "NC_TIMEOUT": 0.0, "NC_JOBS": 1, "TLS_TIMEOUT": 0.0,
    "TLS_THREADS": 1, "MAX_LATENCY_MS": 0.0, "PROBE_TIMEOUT": 0.0,
    "PROBE_WORKERS": 1, "TOP_N": 0,
}
#: Display order for :func:`describe`.
_ORDER: tuple[str, ...] = (
    "MAX_LATENCY_MS", "PING_MAX_TIME_MS", "PING_COUNT", "PING_TIMEOUT",
    "PING_THREADS", "PROBE_TIMEOUT", "NC_TIMEOUT", "PROBE_WORKERS", "NC_JOBS",
    "TLS_TIMEOUT", "TLS_THREADS", "TOP_N",
)
_UNITS: dict[str, str] = {
    "PING_MAX_TIME_MS": "ms", "PING_TIMEOUT": "s", "MAX_LATENCY_MS": "ms",
    "NC_TIMEOUT": "s", "PROBE_TIMEOUT": "s", "TLS_TIMEOUT": "s",
}


def _coerce(name: str, raw: object) -> float | int:
    """Convert ``raw`` to the type declared for ``name``, raising ValueError on junk."""
    if isinstance(raw, bool):
        raise ValueError(f"{name}: expected a number, got a bool ({raw!r})")
    try:
        if name in _INT_NAMES:
            if isinstance(raw, str):
                value: float | int = int(raw.strip(), 10)
            elif isinstance(raw, float):
                if not raw.is_integer():
                    raise ValueError(f"{raw!r} is not a whole number")
                value = int(raw)
            else:
                value = int(raw)  # type: ignore[arg-type]
        else:
            value = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        kind = "an integer" if name in _INT_NAMES else "a float"
        raise ValueError(f"{name}: cannot read {raw!r} as {kind}") from exc

    minimum = _MINIMUMS.get(name)
    if minimum is not None and value < minimum:
        raise ValueError(f"{name}: {value} is below the minimum of {minimum}")
    return value


def _set(name: str, value: float | int) -> None:
    """Assign a validated value to ``name`` and keep its alias in sync."""
    globals()[name] = value
    alias_source = _ALIAS_SOURCES.get(name)
    if alias_source is not None:
        # An alias was set directly, so push it back down to its source name.
        globals()[alias_source] = value
    for alias, source in _ALIAS_SOURCES.items():
        if source == name and alias != name:
            globals()[alias] = value


def apply_overrides(pairs: Iterable[str]) -> None:
    """Apply ``NAME=VALUE`` strings to this module, coercing and validating each.

    Unknown names, unparsable values and out-of-range values raise
    :class:`ValueError`. Every pair is validated before anything is written, so
    a rejected batch leaves the configuration untouched.
    """
    pending: dict[str, float | int] = {}
    for pair in pairs:
        if not isinstance(pair, str) or "=" not in pair:
            raise ValueError(
                f"invalid override {pair!r}: expected NAME=VALUE"
            )
        name, _, raw = pair.partition("=")
        name = name.strip()
        raw = raw.strip()
        if name not in _MINIMUMS:
            known = ", ".join(_ORDER)
            raise ValueError(f"unknown setting {name!r}: known settings are {known}")
        pending[name] = _coerce(name, raw)
    for name, value in pending.items():
        _set(name, value)


def describe() -> str:
    """Render the active configuration, flagging values changed from the defaults."""
    label_width = max(len(name) for name in _ORDER)
    lines = ["Config (active)"]
    for name in _ORDER:
        value = globals()[name]
        if isinstance(value, float):
            shown = f"{value:g}"
        else:
            shown = str(value)
        unit = _UNITS.get(name, "")
        suffix = f" {unit}" if unit else ""
        if DEFAULTS.get(name) != value:
            shown += "  (overridden)"
        origin = _ALIAS_SOURCES.get(name)
        if origin:
            shown += f"  [= {origin}]"
        lines.append(f"  {name:<{label_width}} = {shown}{suffix}")
    return "\n".join(lines)


#: Snapshot of the shipped defaults, taken after the constants above are set.
DEFAULTS: dict[str, float | int] = {
    name: globals()[name] for name in _ORDER  # type: ignore[misc]
}
