# SPDX-License-Identifier: PMPL-1.0-or-later

# Chapel Distributed Orchestrator for panic-attack

Multi-machine scanning via Chapel's `coforall` and locale-based distribution.
Extends panic-attack's single-machine rayon parallelism (assemblyline) to
datacenter-scale scanning across Chapel locales.

## Architecture

```
Locale 0 (coordinator)          Locale 1..N (workers)
┌──────────────────────┐        ┌──────────────────────┐
│ Discover repos       │        │ Receive repo paths   │
│ Partition round-robin│───────►│ Run panic-attack     │
│ Collect results      │◄───────│ BLAKE3 fingerprint   │
│ Build SystemImage    │        │ Stream RepoResult    │
│ Write temporal snap  │        └──────────────────────┘
└──────────────────────┘
```

## Prerequisites

- [Chapel](https://chapel-lang.org/) 2.3.0+
- `panic-attack` binary on PATH (or specify via `--panicAttackBin`)

## Build

```bash
cd chapel
chpl src/MassPanic.chpl src/Protocol.chpl src/Imaging.chpl src/Temporal.chpl -o mass-panic
```

## Usage

### Basic scan (assail only, single machine)

```bash
./mass-panic --repoDirectory=/path/to/repos
```

### Multi-machine cluster scan

```bash
./mass-panic --repoDirectory=/shared/repos --numLocales=32
```

### Full analysis (assail + attack + adjudicate)

```bash
./mass-panic --repoDirectory=/path/to/repos --mode=full --attackTimeout=60
```

### Modes

| Mode | Functions | Speed | Use case |
|------|-----------|-------|----------|
| `assail` | Static analysis | Fast | Risk mapping, imaging |
| `assault` | assail + stress test | Slow | Full stress testing |
| `ambush` | Timeline-driven stress | Slow | Choreographed attacks |
| `adjudicate` | assail + logic verdict | Medium | Bug inference |
| `full` | assail + attack + adjudicate | Slowest | Complete pipeline |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--repoManifest` | | File with one repo path per line |
| `--repoDirectory` | | Directory to scan for .git repos |
| `--panicAttackBin` | `panic-attack` | Path to panic-attack binary |
| `--mode` | `assail` | Operation mode (see above) |
| `--scheduler` | `static` | `static` (fast, not resumable) or `queue` (resumable, ~5–15% slower — v3.0.0) |
| `--resume` | `false` | Only with `--scheduler=queue`: skip repos already marked "done" in the journal |
| `--incremental` | `true` | Skip unchanged repos via BLAKE3 |
| `--cacheFile` | | Fingerprint cache file path |
| `--outputDir` | `mass-panic-results` | Output directory |
| `--verisimdbDir` | `verisimdb-data` | VeriSimDB data directory |
| `--snapshotLabel` | | Label for temporal snapshot |
| `--attackTimeout` | `30` | Seconds per attack axis |
| `--attackAxes` | `all` | Comma-separated axes |
| `--intensity` | `medium` | Attack intensity |
| `--notify` | `false` | Generate notification summary |
| `--panllExport` | `false` | Generate PanLL export files |
| `--quiet` | `false` | Suppress progress output (also suppresses the scheduler banner) |

## Scheduling modes

The `--scheduler` flag is the first decision every `mass-panic` run
implicitly makes. It controls **how work is distributed across
locales**, and the tradeoff matters enough that the tool prints a
banner in both directions at startup (unless `--quiet`) so operators
don't lose overnight sweeps to a Ctrl+C they could have survived.

### `--scheduler=static` — default

Round-robin partition up-front, then `coforall` over Locales. Each
locale gets its fixed list of repos and scans them in-order. This is
the existing implementation and what every previous mass-panic
release has done.

- **Fast.** No per-repo overhead beyond the existing BLAKE3
  fingerprint cache. Chapel's `coforall` amortises scheduling cost
  across the whole range.
- **Not resumable.** A locale crash, a Ctrl+C, or a single failed
  repo halfway through — all force restarting the whole run. The
  completed repos are in `mass-panic-results/assemblyline-*.json`
  but the coordinator hasn't yet merged them into the SystemImage.
- **Right for:** scheduled nightly sweeps over a stable corpus,
  where the run finishes before anyone touches the terminal.

### `--scheduler=queue` — planned, v3.0.0

Dynamic work-pull via a shared atomic counter plus a per-locale
JSONL journal shard. Each locale claims the next unclaimed repo
from a shared counter, writes a `{"state":"claim", …}` entry to
its shard, runs the scan, writes `{"state":"done", …}`.

`--resume` reads every shard, builds the set of fingerprints
already marked `done`, and skips them — so an interrupted run
picks up where it left off.

- **Resumable.** Ctrl+C at t=3h drops ~1 repo of work; the next
  invocation with `--resume` reuses everything completed so far.
  A locale crash during a multi-day sweep loses only the
  currently-in-flight repo on that locale.
- **~5–15% slower** on clean runs. The dispatch overhead per task
  (atomic fetch-add + one journal write) is per-repo instead of
  being amortised across a `coforall` range. On a clean 10k-repo
  sweep, expect queue mode to finish in ~1.10× the time of static.
- **Right for:** long interactive sweeps (GitHub-account scale or
  larger), sweeps where at least one locale is on spot/preemptible
  infrastructure, or any run where you expect to want to pause
  and come back.

#### Why not make queue mode the default?

Static mode is measurably faster on clean runs and doesn't require
any durable state. If your run always finishes cleanly, the journal
writes are wasted I/O. Making the default explicit ("you are in
static mode; here is what you're giving up") lets operators make
that call consciously instead of paying for resilience they don't
need.

#### Current status

`--scheduler=static` is implemented and is the existing behaviour.
`--scheduler=queue` exits with an actionable error message pointing
at this section and `ROADMAP.adoc` (targeted v3.0.0). The flag is
already accepted today so that (a) any tooling that pins `--scheduler=queue`
has a stable CLI contract to write against, and (b) the bail-out is
noisy rather than silent — an operator who asked for resumable
runs must not get a non-resumable one without consent.

### Startup banner

When you run `./mass-panic …`, the scheduler banner appears before
repo discovery:

```
mass-panic: scheduler=static (default)
            fastest on clean runs; no --resume support.
            A crash or Ctrl+C loses all progress.
            Use --scheduler=queue for resumable runs (when available, ~5-15% slower).
```

Or, if you attempt queue mode today:

```
mass-panic: ERROR: --scheduler=queue is not yet implemented.
           Design: atomic work-pull + JSONL journal shards per locale, --resume skips any repo already
           marked "done". See chapel/README.md §Scheduling modes for the full spec and ROADMAP.adoc for
           the targeted landing (v3.0.0).
           Options while you wait: rerun after a crash with --scheduler=static (no incremental state), or use
           the Rust `panic-attack assemblyline` path on a single machine where Ctrl+C is rarer.
```

The banner is suppressed under `--quiet`.

## Output

- `mass-panic-results/assemblyline-<timestamp>.json` — aggregated report
- `mass-panic-results/system-image-<timestamp>.json` — fNIRS-style health map
- `verisimdb-data/` — temporal snapshots (VeriSimDB hexads)

## Relationship to Rust assemblyline

The Chapel layer is **optional**. For single-machine scanning, use:

```bash
panic-attack assemblyline /path/to/repos    # rayon parallel
panic-attack image /path/to/repos           # + imaging + temporal
```

Chapel adds multi-machine distribution for scanning at GitHub-account or
datacenter scale, where hundreds of machines each scan their partition of
repositories simultaneously.
