# proxy_tester

Downloads `vless://`, `vmess://`, `trojan://` and `ss://` proxy link lists,
probes every distinct endpoint with a timed TCP connect, drops what is too slow
or unreachable, TLS-handshakes the survivors, and ranks them by handshake time.

The output is a ranked list of links, one per line, fastest first — plus a
per-run accounting that tells you exactly what happened to every input line.
**Nothing is ever dropped silently**: if a link is lost, the run says how many
and why.

Pure Python 3.10+, **standard library only**. No `pip install`, no external
binaries. `requirements.txt` is empty and stays that way.

---

## The pipeline

Four stages, each reading the previous stage's artifact and writing its own.

**A run leaves exactly one file per source** — `<name>.alive` in the workspace
(`output/` by default). That is the deliverable. The per-stage
intermediates are written to a scratch directory and deleted when the run
finishes, so the workspace never fills up with half-finished artifacts.

| # | Stage | Reads | Writes (all under `<out>/.work/`) | What it does |
|---|-------|-------|-----------------------------------|--------------|
| 1 | decode | `urls.txt`, `local/` | `<name>.de` | Download sources, then base64-decode any subscription payload — including payloads wrapped across lines. |
| 2 | probe | `<name>.de` | `<name>.probe`, `<name>.timings.jsonl` | One timed TCP connect per **distinct** `host:port`; every link sharing an endpoint reuses the result. |
| 3 | latency filter | `<name>.probe` | `<name>.filtered` | Keep endpoints that connected within `MAX_LATENCY_MS`, ascending. |
| 4 | TLS handshake | `<name>.filtered` | `<name>.tls`, `<name>.tls_faulty` | One TLS handshake per distinct `(host, port, sni, insecure)`. Successes ascending by ms; **every** failure is recorded with a reason. |

Step 4's `<name>.tls` is then moved out as the final `<name>.alive`. So
`local/vless.txt` produces exactly one file, `output/vless.txt.alive`.

Pass `--keep-stages` to leave the scratch directory in place when you need to
see where a run threw links away:

```
output/
  vless.txt.alive      <- the result
  .work/               <- only with --keep-stages
    vless.txt.de
    vless.txt.probe
    vless.txt.filtered
    vless.txt.tls_faulty
    vless.txt.timings.jsonl
```

Each stage reads its own previous artifact rather than mutating it in place, so
a stage can never clobber the input it is about to read.

### Every line is accounted for

The run ends with three conservation identities, and exits non-zero if any of
them fails:

```
line balance     10042 in  =  318 duplicate + 4 unparseable + 9720 parsed
parsed balance    9720 parsed  =  8310 endpoint-dead + 210 over-latency + 1200 tls-tested
tls balance        1200 tested  =  1180 ok + 20 failed
```

A link ends up in exactly one bucket: `duplicate`, `unparseable`,
`endpoint-dead`, `over-latency`, or `tls-tested` (which then splits into
`tls ok` / `tls failed`). If the arithmetic does not close, the run tells you.

---

## Install

```sh
git clone https://github.com/magichrist/proxy_tester.git
cd proxy_tester
python3 start.py --help
```

That is the whole install. Python 3.10 or newer, nothing else. `requirements.txt`
is intentionally empty.

> `chmod +x nc_test.sh` from older versions of this README is **no longer needed** —
> `nc_test.sh` and `ping_test.py` have been deleted. Everything is pure Python now.

---

## Usage

```sh
python3 start.py                              # download everything, process it
python3 start.py --no-url --limit 300         # smoke-test local/ only
python3 start.py --no-url --top 5 --quiet     # tighter report, no banner
python3 start.py --set MAX_LATENCY_MS=300     # tighten the latency threshold
python3 start.py --out /tmp/run --keep        # keep the previous workspace
```

All paths resolve relative to `start.py`, not your current directory, so
`python3 /anywhere/proxy_tester/start.py` behaves the same from anywhere.

### Flags

| Flag | Meaning |
|------|---------|
| `--no-url` | Skip downloads. Process only `local/` (and any leftover artifacts in the workspace). |
| `--limit N` | Process only the first `N` links of every input file. Useful for a fast smoke test. |
| `--top N` | How many of the best results to highlight at the end. Default `Config.TOP_N` (20). |
| `--set KEY=VALUE` | Override any Config constant. Repeatable. Unknown keys and bad values are rejected before anything runs. |
| `--workers N` | Probe and TLS concurrency. Shorthand for `--set PROBE_WORKERS=N --set TLS_THREADS=N`. |
| `--max-latency MS` | Latency threshold in ms. Shorthand for `--set MAX_LATENCY_MS=MS`. |
| `--out DIR` | Workspace directory. Default `output/` next to `start.py`. |
| `--keep` | Do **not** wipe the workspace before running. Default: wipe it. |
| `--keep-stages` | Keep the per-stage scratch files in `<out>/.work/`. Default: delete them, leaving only `<name>.alive`. The scratch `<name>.tls` is the only place the per-link latency survives. |
| `--color` / `--no-color` | Force ANSI colour on or off. Default: on only when stdout is a terminal, honouring `NO_COLOR` and `FORCE_COLOR`. |
| `--quiet` | Suppress the banner and the active-config dump, for CI and pipes. |

`--set` is applied first; the shorthand flags (`--max-latency`, `--workers`,
`--top`) are applied afterwards and therefore win.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Ran, and every conservation identity closed. |
| `1` | An accounting mismatch, or every input file failed. |
| `2` | Bad usage: an unknown `--set` key, an unparseable value, or a negative/zero out-of-range flag. |

---

## Configuration

Every setting is a plain constant in `Config.py`. The old names still resolve —
`from Config import *` is public API and keeps working.

| Constant | Default | Unit | Meaning |
|----------|---------|------|---------|
| `MAX_LATENCY_MS` | `800.0` | ms | Latency threshold. Links slower than this are dropped after the probe stage. Canonical name for `PING_MAX_TIME_MS`. |
| `PING_MAX_TIME_MS` | `800.0` | ms | Legacy name for `MAX_LATENCY_MS`. Setting either updates the other. |
| `PING_COUNT` | `1` | — | Legacy. The TCP probe is a single sample, so this is always 1. Kept so old code and configs do not break. |
| `PING_TIMEOUT` | `1.0` | **seconds** | Legacy name for `PROBE_TIMEOUT`. Unambiguously seconds on every platform. |
| `PING_THREADS` | `30` | — | Legacy. Prefer `PROBE_WORKERS`. |
| `PROBE_TIMEOUT` | `1.0` | **seconds** | Per-connect timeout for the TCP probe. Setting either updates `NC_TIMEOUT`. |
| `NC_TIMEOUT` | `1.0` | **seconds** | Legacy name for `PROBE_TIMEOUT`. |
| `PROBE_WORKERS` | `30` | — | Concurrent TCP connects. Setting either updates `NC_JOBS`. |
| `NC_JOBS` | `30` | — | Legacy name for `PROBE_WORKERS`. |
| `TLS_TIMEOUT` | `3.0` | **seconds** | Per-handshake timeout. Longer than the probe timeout because a TLS handshake costs a full round trip. |
| `TLS_THREADS` | `30` | — | Concurrent TLS handshakes. |
| `TOP_N` | `20` | — | How many best results the final report highlights. |

Three things changed since the old README, and they matter:

- **`PING_TIMEOUT` is now seconds.** It was ambiguous across platforms before.
- **`PING_MAX_TIME_MS` is a TCP connect time, not an ICMP ping time.** The
  number is still milliseconds; what it measures is not. See below.
- **`NC_TIMEOUT` / `NC_JOBS` no longer refer to netcat.** Nothing shells out any
  more. They are kept as aliases of `PROBE_TIMEOUT` / `PROBE_WORKERS`.

### Overriding from the CLI

```sh
python3 start.py --set MAX_LATENCY_MS=300 --set PROBE_TIMEOUT=2.0 --set TLS_THREADS=64
```

Overrides are validated up front and applied atomically: if any value in the
batch is unknown, unparseable, or below its minimum, the run aborts with exit
code 2 and **nothing is changed**. The alias pairs stay in sync whichever side
you set — `--set NC_TIMEOUT=2.5` also sets `PROBE_TIMEOUT=2.5`, and vice versa.

The active configuration is printed at startup unless you pass `--quiet`.

---

## Output format

**`<name>.alive` holds bare links, one per line, fastest first** — no timing
column, nothing to strip before importing into a client:

```
vless://10cb2689-72fc-418d-8d21-cf625e558bec@212.64.210.109:443?security=reality&…
vless://121a027a-7839-42d5-8223-9b7a3d0311e6@104.16.159.188:2083?type=ws&…
```

The latency is not thrown away — it is what determined the order, and it is
still shown in the run summary and in the `--top N` listing. If you want the
timings as data, re-run with `--keep-stages` and read
`output/.work/<name>.tls`, which keeps the internal scored format:

```
<ms>\t<link>
```

Milliseconds first, one literal tab, then the **unmodified** original link —
ascending by ms, numerically. The link text is echoed back byte-for-byte,
including links whose query or fragment contains a `#`, a tab, or non-ASCII
characters. Nothing is ever appended to or rewritten inside the link.

Order is preserved when the timing column is dropped, so `head -n 10` on
`<name>.alive` still gives the ten fastest. If you ever do need to split a
scored file by hand, split on the **first** tab only — a link may itself
contain one:

```sh
cut -f2- output/.work/vless.txt.tls | head -n 10
```

### The artifacts

There is one artifact per run. `<name>.alive` is the deliverable:

| File | Contents |
|------|----------|
| `<name>.alive` | **The answer.** Every link that passed all four stages, bare, fastest first. |

Everything else is scratch. With `--keep-stages` it stays in `<out>/.work/`:

| Scratch file | Contents |
|--------------|----------|
| `<name>.de` | Decoded links, one per line, exactly as they will be parsed. |
| `<name>.probe` | Links whose endpoint completed a TCP connect. Still bare links, no timing. |
| `<name>.filtered` | The subset that connected within `MAX_LATENCY_MS`, ascending by ms. |
| `<name>.tls_faulty` | **Every** TLS failure, as `<ms>\t<link>` when a timing is known or `<reason>\t<link>` when it is not. Nothing is dropped here. |
| `<name>.timings.jsonl` | One JSON object per distinct endpoint — the raw measurements. |

`_faulty` exists so that a suspicious result is never silently swallowed. If the
`.alive` file looks too good, re-run with `--keep-stages` and check
`.work/<name>.tls_faulty`: it is where the links that parsed but could not
complete a handshake went, with the reason
(`refused`, `timeout`, `dns`, `unreachable`, `cert`, `tls`, `parse`, `other`).
The run summary reports the TLS-failure count either way, so you do not need
`--keep-stages` to know whether links were dropped.

`timings.jsonl` is the per-endpoint measurement record, one object per line:

```json
{"endpoint":"198.51.100.7:443","host":"198.51.100.7","port":443,"ok":true,"ms":42.31,"error":null}
{"endpoint":"198.51.100.8:443","host":"198.51.100.8","port":443,"ok":false,"ms":null,"error":"timeout"}
```

It is what lets the latency filter re-run without re-probing, and it is the
first place to look when a number in the output surprises you. `ms` is `null` on
failure, never `0` — a failed measurement is not a fast one.

---

## Adding your own sources

### `urls.txt`

One URL per line. Blank lines and lines starting with `#` are ignored. Anything
the server returns is accepted: a plain link list, a base64 payload, or a
base64 payload wrapped across lines.

```
# public configs
https://example.invalid/v2ray/vless.txt
https://example.invalid/subscriptions/trojan
```

Downloaded bodies are saved into the workspace under a sanitised filename
derived from `Content-Disposition` or the URL path, so a source that serves
`vless.txt?foo=1&bar=2` still lands as a readable file.

### `local/`

Drop your own link files in `local/`. The directory is created if it does not
exist. Files are copied into the workspace and processed alongside everything
else, so a local file and a downloaded source are treated identically. If a
local file has the same name as a download, it is saved as `local_<name>`
rather than overwriting it.

If a run finds no new input at all (`--no-url` with an empty `local/`), it
re-uses the `<name>.alive` left by the previous run and refreshes it in place,
so re-running to re-check a shortlist is just:

```sh
python3 start.py --no-url
```

Nothing is renamed and no second copy appears — the workspace keeps exactly one
file per source no matter how many times you run it.

---

## Why a TCP connect instead of ping

The old tool measured latency with an ICMP `ping`. That is the wrong tool for
this job, for two reasons that show up in real data:

1. **These endpoints are almost all Cloudflare/CDN anycast addresses.** An ICMP
   echo to an anycast address measures you-to-*edge*, not you-to-*proxy*. Two
   completely different proxies behind the same anycast IP get the same "ping"
   number, and the number reflects whichever edge your ISP happened to route to
   this time. It is not a property of the proxy at all.

2. **Many CDN edges drop ICMP entirely.** A perfectly good proxy gets reported
   "unreachable" or "timeout" because the edge in front of it declines to answer
   pings. That silently removed good proxies from the results.

A timed TCP connect measures the thing you actually care about: can I open a
connection to this endpoint, and how long does it take. If the connect succeeds,
the proxy is reachable — there is no inference step. It is also one syscall pair
instead of a subprocess, which is what makes the measurement cache possible
(see below).

The cost is that `MAX_LATENCY_MS` is now a *connect* threshold rather than a
*ping* threshold, so the absolute numbers are not comparable with older runs of
this tool. The relative ranking is much more trustworthy.

### The measurement cache

One TCP connect per **distinct** `host:port`, not per link. Ten thousand links
spread over a thousand endpoints issue a thousand connects, not ten thousand.
Every link sharing an endpoint reuses that endpoint's result, and the same
measurements are carried forward between stages so the latency filter never
re-probes what the probe stage just measured.

---

## Development

```sh
python3 -m unittest discover -s tests -v
```

The suite is stdlib `unittest` and runs fully **offline** in well under a
second: every socket it opens is a loopback listener on an ephemeral port, and
`tests/support.py` installs a guard at import time that raises if any test tries
to connect to a non-loopback address or resolve a non-loopback name. A handful
of tests are marked `@unittest.expectedFailure`; they document known defects
rather than pretending they pass.

| Module | Role |
|--------|------|
| `links.py` | The single source of truth for parsing: scheme, host, port, SNI, and the dedup identity. |
| `netprobe.py` | The timed TCP-connect prober and the measurement cache. |
| `tls_test.py` | The TLS handshake stage. |
| `Config.py` | Every tunable constant, plus `apply_overrides()`. |
| `progress.py` | Terminal progress reporting; degrades to sparse lines when stdout is not a TTY. |
| `base64_decryptor.py` | Subscription payload decoding. |
| `start.py` | The orchestrator: downloads, stages, conservation report. |
