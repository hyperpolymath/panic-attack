# SPDX-License-Identifier: MPL-2.0

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
| `--scheduler` | `static` | `static` (fast, not resumable) or `queue` (resumable, ~5–15% slower) |
| `--resume` | `false` | Only with `--scheduler=queue`: skip repos already marked "done" in the journal |
| `--journalDir` | `<outputDir>/journal` | Directory for queue-scheduler JSONL shards |
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

### `--scheduler=queue`

Dynamic work-pull via a shared atomic counter plus a per-locale
JSONL journal shard. Each locale claims the next unclaimed repo
from a shared counter, writes a `{"state":"claim", …}` entry to
its shard, runs the scan, writes `{"state":"done", …}` with the
full RepoResult payload (weak-point count, severities, fingerprint,
verdict, error).

`--resume` reads every shard in `<journalDir>`, extracts the latest
`done` entry per repo path, reconstructs the RepoResult records,
and skips those repos on the new run — so an interrupted run picks
up where it left off and the final report covers both the
previously-completed repos and the freshly-scanned ones.

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

Both schedulers are implemented. `--scheduler=static` is the default
and preserves the previous behaviour exactly — selecting `queue` does
not make static slower. `--scheduler=queue` writes per-run shards
(`locale-<id>-<runId>.jsonl`) so a crashed run's partial shard stays
isolated from the next run's writes; `--resume` replays every shard
in the journal directory and merges prior results with fresh ones.

The atomic work counter lives on the coordinator (Locale 0); every
claim is one remote fetchAdd (microseconds) against a scan cost of
100ms–60s, so the dispatch overhead is well under 1% on any real
workload. The ~5–15% figure above accounts for the per-repo journal
write + flush, not the atomic itself.

### Startup banner

When you run `./mass-panic …`, the scheduler banner appears before
repo discovery:

```
mass-panic: scheduler=static (default)
            fastest on clean runs; no --resume support.
            A crash or Ctrl+C loses all progress.
            Use --scheduler=queue for resumable runs (~5-15% slower).
```

Or for queue mode:

```
mass-panic: scheduler=queue
           resumable via --resume; per-locale JSONL shards at mass-panic-results/journal
           ~5-15% slower than static on clean runs (one atomic + one journal write per repo).
           A crash or Ctrl+C loses only the in-flight repo per locale — everything already
           marked "done" is skipped on the next invocation with --resume.
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
