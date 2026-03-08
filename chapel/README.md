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
| `--quiet` | `false` | Suppress progress output |

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
