// SPDX-License-Identifier: PMPL-1.0-or-later

//
// MassPanic — Chapel distributed orchestrator for panic-attack
//
// Distributes static analysis scanning across Chapel locales (machines) for
// datacenter-scale codebase imaging. Each locale runs the `panic-attack`
// binary locally on its partition of repositories, streaming results back
// for aggregation into a system-wide health image.
//
// Architecture:
//   Locale 0 (coordinator):
//     - Discovers repos from manifest or filesystem walk
//     - Partitions work across locales using round-robin or affinity
//     - Collects results and builds the unified SystemImage
//     - Writes temporal snapshots to VeriSimDB
//
//   Locale 1..N (workers):
//     - Receive repo paths from coordinator
//     - Run `panic-attack assail --output-format json` per repo
//     - Compute BLAKE3 fingerprints for incremental skip
//     - Stream RepoResult JSON back to coordinator
//
// Usage:
//   chpl src/MassPanic.chpl -o mass-panic
//   ./mass-panic --repoManifest=repos.txt --panicAttackBin=panic-attack
//   ./mass-panic --repoManifest=repos.txt --numLocales=32  # 32-machine cluster
//
// The Chapel layer is strictly optional — the Rust `assemblyline` module
// provides single-machine rayon parallelism. Chapel adds multi-machine
// distribution for scanning at GitHub-account or datacenter scale.
//

module MassPanic {
    use IO;
    use FileSystem;
    use Time;
    use List;
    use Map;
    use Sort;
    use Subprocess;
    use Path;

    use Protocol;
    use Imaging;
    use Temporal;

    // ---------------------------------------------------------------------------
    // Configuration (command-line overrideable)
    // ---------------------------------------------------------------------------

    config const repoManifest: string = "";
    config const repoDirectory: string = "";
    config const panicAttackBin: string = "panic-attack";
    config const outputDir: string = "mass-panic-results";
    config const incremental: bool = true;
    config const cacheFile: string = "";
    config const maxReposPerLocale: int = 0; // 0 = unlimited
    config const verisimdbDir: string = "verisimdb-data";
    config const snapshotLabel: string = "";
    config const imagingOutput: string = "";
    config const quiet: bool = false;
    config const findingsOnly: bool = false;

    // Top-level subcommand: "scan" (default) or "diff"
    // diff: compare two temporal snapshots and print a delta report
    config const subcommand: string = "scan";

    // diff subcommand options:
    //   --diffFrom=snap-1   snapshot ID from temporal index (default: second-to-last)
    //   --diffTo=snap-2     snapshot ID from temporal index (default: latest)
    //   --diffOutput=path   write diff JSON to file instead of stdout
    config const diffFrom: string = "";
    config const diffTo: string = "";
    config const diffOutput: string = "";

    // Operation mode: which panic-attack functions to run per repo
    // "assail"      — static analysis only (default, fastest)
    // "assault"     — full stress test (assail + attack)
    // "ambush"      — timeline-based stress test
    // "adjudicate"  — verdict via miniKanren logic engine
    // "full"        — run all applicable functions (assail + attack + adjudicate)
    config const mode: string = "assail";

    // Per-repo attack options (for assault/ambush modes)
    config const attackTimeout: int = 30;     // seconds per attack axis
    config const attackAxes: string = "all";  // "all" or comma-separated: "cpu,memory,disk"
    config const intensity: string = "medium";

    // Notification options
    config const notify: bool = false;
    config const notifyCriticalOnly: bool = true;

    // PanLL export alongside raw output
    config const panllExport: bool = false;

    // Scheduler — controls how work is distributed across locales.
    //
    //   "static" (default)
    //     Round-robin partition + `coforall` over Locales. Fast, clean,
    //     but a mid-scan crash loses progress — the whole run must be
    //     restarted because no per-repo state is durably recorded.
    //     Best for scheduled nightly sweeps over stable corpora.
    //
    //   "queue"
    //     Dynamic work-pull via a shared atomic counter + per-locale
    //     JSONL journal shards. Each locale claims the next unclaimed
    //     repo, writes a "claim" entry, scans, writes "done" with the
    //     full RepoResult payload.  `--resume` replays every shard's
    //     "done" entries and skips those repos on the next run.
    //     ~5–15% slower than static on clean runs; survives mid-scan
    //     crashes and Ctrl+C — only the in-flight repo per locale is
    //     lost. Best for long interactive sweeps or any run where you
    //     might pause and resume.
    //
    // Selecting queue does NOT make static slower — the static path
    // stays exactly as it was before the queue implementation. The
    // flag is additive.
    config const scheduler: string = "static";

    // Resume from a previous --scheduler=queue run by skipping any repo
    // already marked "done" in the journal. Only meaningful with
    // --scheduler=queue; ignored (with a warning) in static mode.
    config const resume: bool = false;

    // Journal directory for queue-scheduler shards. Defaults to
    // <outputDir>/journal. Each run writes one shard per locale:
    //   locale-<id>-<runId>.jsonl
    // Per-run filenames avoid requiring append-mode I/O and keep
    // crash-interrupted shards isolated from the next run's writes.
    config const journalDir: string = "";

    // ---------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------

    proc main() {
        // Route to diff subcommand before doing any scanning
        if subcommand == "diff" {
            runDiff();
            return;
        }

        // Validate --scheduler and print the running-mode banner. Both
        // modes get an explicit banner (not only the non-default one)
        // because the tradeoff is real in both directions — static is
        // fast but not resumable; queue is resumable but slower. See
        // chapel/README.md §Scheduling modes for the full discussion.
        if !selectAndAnnounceScheduler() then return;

        const startTime = timeSinceEpoch().totalSeconds();

        // Discover repositories
        var repos = discoverRepos();
        if repos.size == 0 {
            writeln("mass-panic: no repositories found");
            return;
        }

        if !quiet then
            writeln("mass-panic: ", repos.size, " repos across ", numLocales, " locales");

        // Load fingerprint cache for incremental scanning
        var cache = loadFingerprintCacheFromFile(cacheFile);

        // Dispatch to the selected scheduler. Both paths populate the
        // same `results` list and share the downstream pipeline
        // (sort → filter → image → report → snapshot).
        var results: list(RepoResult);
        if scheduler == "queue" {
            runQueueScan(repos, cache, results);
        } else {
            runStaticScan(repos, cache, results);
        }

        // Collect and sort results
        var resultsArr = results.toArray();
        sort(resultsArr, comparator=new ResultComparator());

        // Filter to only repos with findings if --findingsOnly.
        // Always build via list to avoid Chapel array-shape mismatch on assignment.
        var filteredList: list(RepoResult);
        for r in resultsArr {
            if !findingsOnly || r.weakPointCount > 0 || r.error != "" then
                filteredList.pushBack(r);
        }
        var filteredResults = filteredList.toArray();

        // Build system image
        var image = buildSystemImage(filteredResults, repos.size);

        // Populate timestamp and surface fields before any output
        const nowStr = dateString();
        image.generatedAt = nowStr;
        image.scanSurface = if repoDirectory != "" then repoDirectory
                            else if repoManifest != "" then "manifest:" + repoManifest
                            else "unknown";

        // Build assemblyline-compatible report
        var report = buildReport(filteredResults, repos.size, repoDirectory, startTime);
        report.createdAt = nowStr;

        // Write outputs
        writeOutputs(report, image, filteredResults);

        // Take temporal snapshot
        if verisimdbDir != "" {
            takeSnapshot(image, report, verisimdbDir, snapshotLabel);
        }

        if !quiet then
            printSummary(report, image);
    }

    // ---------------------------------------------------------------------------
    // Scheduler selection — validate --scheduler and print the
    // running-mode banner in both directions. See chapel/README.md
    // §Scheduling modes for the full tradeoff discussion.
    //
    // Why both modes get a banner (not only the non-default one):
    //
    //   The static default is fast and ergonomically invisible, but
    //   its non-resumability is a real correctness property of the run
    //   — operators need to *know* that a Ctrl+C at t=3h is wasted
    //   work. Silently accepting the default is how people lose
    //   overnight sweeps and don't realise until morning.
    //
    //   The queue mode pays a ~5–15% throughput tax for resilience,
    //   so we tell operators running that path that they are trading
    //   clean-run speed for crash recovery. If their run completes
    //   cleanly they might prefer static next time.
    //
    // The banner is suppressed under --quiet, along with everything
    // else.
    // ---------------------------------------------------------------------------

    // Returns true if mass-panic should proceed with scanning, false
    // if it should bail cleanly. Writing the banner/error messages is
    // the side effect.
    proc selectAndAnnounceScheduler(): bool {
        if scheduler == "static" {
            if !quiet {
                writeln("mass-panic: scheduler=static (default)");
                writeln("           fastest on clean runs; no --resume support.");
                writeln("           A crash or Ctrl+C loses all progress.");
                writeln("           Use --scheduler=queue for resumable runs ",
                        "(~5-15% slower).");
            }
            if resume {
                writeln("mass-panic: WARNING: --resume ignored — ",
                        "requires --scheduler=queue");
            }
            return true;
        } else if scheduler == "queue" {
            if !quiet {
                writeln("mass-panic: scheduler=queue");
                writeln("           resumable via --resume; ",
                        "per-locale JSONL shards at ", resolvedJournalDir());
                writeln("           ~5-15% slower than static on clean runs ",
                        "(one atomic + one journal write per repo).");
                writeln("           A crash or Ctrl+C loses only the ",
                        "in-flight repo per locale — everything already");
                writeln("           marked \"done\" is skipped on the next ",
                        "invocation with --resume.");
            }
            return true;
        } else {
            writeln("mass-panic: ERROR: unknown --scheduler=", scheduler,
                    " — expected 'static' or 'queue'");
            return false;
        }
    }

    // ---------------------------------------------------------------------------
    // Static scheduler — round-robin partition + coforall over locales.
    // This is the existing behaviour, factored out of main() so that
    // main() can dispatch uniformly to either scheduler.
    // ---------------------------------------------------------------------------

    proc runStaticScan(ref repos: list(string), ref cache: FingerprintCache,
                        ref results: list(RepoResult)) {
        // Partition repos across locales (round-robin)
        var partitions: [0..#numLocales] list(string);
        for (repo, idx) in zip(repos, 0..) {
            const localeId = idx % numLocales;
            partitions[localeId].pushBack(repo);
        }

        // Distributed scan — each locale processes its partition
        var allResults: [0..#repos.size] RepoResult;
        var resultIdx: atomic int;

        coforall loc in Locales with (ref allResults, ref resultIdx) do on loc {
            const myPartition = partitions[loc.id];
            for repo in myPartition {
                var result = scanRepo(repo, cache);
                const slot = resultIdx.fetchAdd(1);
                if slot < repos.size then
                    allResults[slot] = result;
            }
        }

        const actualCount = resultIdx.read();
        for i in 0..#actualCount {
            results.pushBack(allResults[i]);
        }
    }

    // ---------------------------------------------------------------------------
    // Queue scheduler — shared-atomic work-pull + per-locale JSONL journal.
    //
    // Design (see chapel/README.md §Scheduling modes for the full spec):
    //
    //   1. One atomic work index lives on Locale 0. Every locale's
    //      inner loop calls `workIdx.fetchAdd(1)`; remote RMA cost
    //      (~μs) is dwarfed by per-repo scan cost (~100ms to 60s).
    //
    //   2. Each locale opens its own JSONL shard file for this run at
    //      `<journalDir>/locale-<id>-<runId>.jsonl`. Per-run filenames
    //      avoid requiring append-mode semantics across Chapel versions
    //      and keep a crashed run's shard isolated from the next run.
    //
    //   3. For each claimed repo, the locale writes a {"state":"claim"}
    //      entry, flushes, runs the scan, writes {"state":"done",…}
    //      with the full RepoResult payload, flushes. Both flushes are
    //      deliberate: we want the done entry on disk before the next
    //      fetchAdd so that a kill -9 between iterations does not lose
    //      the completed scan's result.
    //
    //   4. `--resume` loads every `locale-*.jsonl` shard in journalDir,
    //      extracts the latest "done" entry per repo path, reconstructs
    //      RepoResult records, and skips those repos on the new run.
    //      Previous results are merged back into `results` so the final
    //      report covers all repos, not only freshly-scanned ones.
    //
    // Losing only the in-flight repo per locale (rather than the whole
    // run) is the whole point of queue mode; the claim/done pairing is
    // the key invariant — never write "done" before the scan actually
    // completed, and never write "claim" without then writing "done" or
    // leaving a clear gap for the next resume to re-claim.
    // ---------------------------------------------------------------------------

    proc runQueueScan(ref repos: list(string), ref cache: FingerprintCache,
                       ref results: list(RepoResult)) {
        const jdir = resolvedJournalDir();
        try { mkdir(jdir, parents=true); } catch { }

        // Load prior "done" entries if --resume. These are authoritative
        // RepoResult records from previous runs; we replay them into
        // `results` before scanning the remaining (pending) repos.
        var prior: map(string, RepoResult);
        if resume {
            prior = loadJournalDone(jdir);
            if !quiet then
                writeln("mass-panic: --resume: ", prior.size,
                        " repo(s) previously marked done; skipping");
        }

        // Partition: anything not in prior is pending. Emit prior first —
        // sort order does not matter, the downstream sort handles it.
        for k in prior.keys() {
            results.pushBack(try! prior[k]);
        }

        var pendingList: list(string);
        for r in repos {
            if !prior.contains(r) then pendingList.pushBack(r);
        }
        const pendingCount = pendingList.size;

        if !quiet then
            writeln("mass-panic: queue scheduler: ", pendingCount,
                    " pending / ", repos.size, " total across ",
                    numLocales, " locales");

        if pendingCount == 0 then return;

        // Freeze pending repos into a shared-visible array. Strings
        // live wherever the coordinator built them; remote reads from
        // workers are one-shot and cheap compared to scan cost.
        var pendingRepos: [0..#pendingCount] string;
        for (r, i) in zip(pendingList, 0..) { pendingRepos[i] = r; }

        // One-shot runId for this invocation, used in shard filenames
        // to separate this run's output from previous runs' shards.
        const runId = dateString();

        // Shared atomic work counter. Lives on the coordinator (Locale 0)
        // by default; workers issue remote fetchAdd.
        var workIdx: atomic int;
        workIdx.write(0);

        // Fresh-results slab, one RepoResult per pending repo.
        var freshResults: [0..#pendingCount] RepoResult;
        var resultSlot: atomic int;

        coforall loc in Locales
            with (ref freshResults, ref resultSlot, ref workIdx) do on loc {

            const shardPath = joinPath(
                jdir,
                "locale-" + loc.id:string + "-" + runId + ".jsonl"
            );

            try {
                var shardFile = open(shardPath, ioMode.cw);
                var journal = shardFile.writer(locking=true);

                while true {
                    const idx = workIdx.fetchAdd(1);
                    if idx >= pendingCount then break;

                    const repo = pendingRepos[idx];

                    const claimTs = dateString();
                    try { writeJournalClaim(journal, loc.id, repo, claimTs); }
                    catch { }
                    try { journal.flush(); } catch { }

                    var result = scanRepo(repo, cache);

                    const doneTs = dateString();
                    try { writeJournalDone(journal, loc.id, repo, doneTs, result); }
                    catch { }
                    try { journal.flush(); } catch { }

                    const slot = resultSlot.fetchAdd(1);
                    if slot < pendingCount then
                        freshResults[slot] = result;
                }

                try { journal.close(); } catch { }
                try { shardFile.close(); } catch { }
            } catch e: Error {
                writeln("mass-panic: locale ", loc.id,
                        " journal error: ", e.message());
            }
        }

        const freshCount = resultSlot.read();
        for i in 0..#freshCount {
            results.pushBack(freshResults[i]);
        }
    }

    // ---------------------------------------------------------------------------
    // Journal helpers (queue scheduler)
    // ---------------------------------------------------------------------------

    // Resolve the journal directory, defaulting to <outputDir>/journal
    // when --journalDir was not explicitly set.
    proc resolvedJournalDir(): string {
        if journalDir != "" then return journalDir;
        return joinPath(outputDir, "journal");
    }

    // JSON-escape a string for embedding in a journal entry. Only
    // backslash and double-quote need escaping for our inputs (repo
    // paths, fingerprints, verdict/error strings from panic-attack
    // output — control chars are rare enough that a round-trip is
    // still readable if they appear; the loader uses a liberal parser).
    proc journalEscape(s: string): string {
        var out: string;
        for ch in s {
            if ch == "\\" then out += "\\\\";
            else if ch == "\"" then out += "\\\"";
            else out += ch;
        }
        return out;
    }

    // Write a {"state":"claim",…} journal entry on a single JSONL line.
    proc writeJournalClaim(writer, localeId: int, repo: string, ts: string)
        throws {
        writer.writeln("{\"state\":\"claim\",\"locale\":", localeId,
                       ",\"repo\":\"", journalEscape(repo),
                       "\",\"ts\":\"", ts, "\"}");
    }

    // Write a {"state":"done",…} journal entry carrying the full
    // RepoResult payload. Category list is omitted — imaging heat
    // maps are regenerated from the scan output itself, not from the
    // journal; the journal exists to say "this repo is complete, here
    // are its counts" for resumed-run aggregation.
    proc writeJournalDone(writer, localeId: int, repo: string, ts: string,
                          const ref result: RepoResult) throws {
        writer.writeln("{\"state\":\"done\",\"locale\":", localeId,
                       ",\"repo\":\"", journalEscape(repo),
                       "\",\"ts\":\"", ts,
                       "\",\"fingerprint\":\"", journalEscape(result.fingerprint),
                       "\",\"weak_point_count\":", result.weakPointCount,
                       ",\"critical_count\":", result.criticalCount,
                       ",\"high_count\":", result.highCount,
                       ",\"total_files\":", result.totalFiles,
                       ",\"total_lines\":", result.totalLines,
                       ",\"crashes\":", result.crashes,
                       ",\"skipped\":",
                           if result.skipped then "true" else "false",
                       ",\"verdict\":\"", journalEscape(result.verdict),
                       "\",\"error\":\"", journalEscape(result.error), "\"}");
    }

    // Replay every `locale-*.jsonl` shard in `dir`, extract all
    // "done" entries, and return the latest-wins map from repoPath
    // to reconstructed RepoResult. A corrupt or half-written last
    // line in one shard (e.g. kill -9 mid-write) is skipped without
    // failing the whole load — the parser treats non-matching lines
    // as silent no-ops.
    proc loadJournalDone(dir: string): map(string, RepoResult) {
        var done: map(string, RepoResult);
        if !safeIsDir(dir) then return done;

        for entry in listDir(dir, dirs=false, files=true) {
            if !entry.startsWith("locale-") || !entry.endsWith(".jsonl") then
                continue;
            const shardPath = joinPath(dir, entry);
            try {
                var f = open(shardPath, ioMode.r);
                var reader = f.reader(locking=false);
                var line: string;
                while reader.readLine(line, stripNewline=true) {
                    const trimmed = line.strip();
                    if trimmed == "" then continue;
                    // Only interested in done entries; claims are just
                    // in-flight markers and don't carry result fields.
                    if trimmed.find("\"state\":\"done\"") == -1 then continue;

                    var r: RepoResult;
                    r.repoPath        = extractQuotedString(trimmed, "\"repo\":");
                    if r.repoPath == "" then continue;
                    r.repoName        = basename(r.repoPath);
                    r.fingerprint     = extractQuotedString(trimmed, "\"fingerprint\":");
                    r.verdict         = extractQuotedString(trimmed, "\"verdict\":");
                    r.error           = extractQuotedString(trimmed, "\"error\":");
                    r.weakPointCount  = extractInt(trimmed, "\"weak_point_count\":");
                    r.criticalCount   = extractInt(trimmed, "\"critical_count\":");
                    r.highCount       = extractInt(trimmed, "\"high_count\":");
                    r.totalFiles      = extractInt(trimmed, "\"total_files\":");
                    r.totalLines      = extractInt(trimmed, "\"total_lines\":");
                    r.crashes         = extractInt(trimmed, "\"crashes\":");
                    r.skipped         = trimmed.find("\"skipped\":true") != -1;
                    // Latest wins (re-scan after partial failure overrides prior).
                    done[r.repoPath] = r;
                }
            } catch {
                writeln("mass-panic: WARNING: could not read journal shard ",
                        shardPath);
            }
        }
        return done;
    }

    // ---------------------------------------------------------------------------
    // Diff subcommand — compare two temporal snapshots
    // ---------------------------------------------------------------------------

    proc runDiff() {
        const indexPath = joinPath(verisimdbDir, "temporal-index.json");
        var snapshots = loadSnapshotSummaries(indexPath);

        if snapshots.size == 0 {
            writeln("mass-panic diff: no temporal snapshots found in ", indexPath);
            writeln("  Run a scan first: ./mass-panic --repoDirectory=<path>");
            return;
        }

        if snapshots.size < 2 {
            writeln("mass-panic diff: need at least 2 snapshots to diff (found ", snapshots.size, ")");
            return;
        }

        // Resolve --diffFrom and --diffTo (default: last two snapshots)
        var fromSnap: TemporalSnapshot;
        var toSnap: TemporalSnapshot;
        var fromFound = false;
        var toFound = false;

        if diffFrom == "" && diffTo == "" {
            // Default: diff latest two
            fromSnap = snapshots[snapshots.size - 2];
            toSnap   = snapshots[snapshots.size - 1];
            fromFound = true;
            toFound   = true;
        } else {
            for snap in snapshots {
                if !fromFound && (diffFrom == "" || snap.id == diffFrom || snap.sequenceNumber:string == diffFrom) {
                    fromSnap   = snap;
                    fromFound  = true;
                }
                if !toFound && (diffTo == "" || snap.id == diffTo || snap.sequenceNumber:string == diffTo) {
                    toSnap  = snap;
                    toFound = true;
                }
            }
            // If only one side was specified, fall back to adjacent defaults
            if fromFound && !toFound then { toSnap = snapshots[snapshots.size - 1]; toFound = true; }
            if toFound && !fromFound then { fromSnap = snapshots[0]; fromFound = true; }
        }

        if !fromFound || !toFound {
            writeln("mass-panic diff: could not resolve snapshot IDs");
            writeln("  --diffFrom=", diffFrom, "  --diffTo=", diffTo);
            writeln("  Available: ");
            for snap in snapshots {
                writeln("    ", snap.id, "  seq=", snap.sequenceNumber,
                        "  ts=", snap.timestamp,
                        if snap.tag != "" then "  label=" + snap.tag else "");
            }
            return;
        }

        // Build SystemImage objects. Start with summary metrics (always available),
        // then load per-node data from saved image files when paths are present.
        var olderImg: SystemImage;
        olderImg.generatedAt    = fromSnap.timestamp;
        olderImg.globalHealth   = fromSnap.globalHealth;
        olderImg.globalRisk     = fromSnap.globalRisk;
        olderImg.totalWeakPoints= fromSnap.totalWeakPoints;
        olderImg.totalCritical  = fromSnap.totalCritical;
        olderImg.reposScanned   = fromSnap.reposScanned;
        olderImg.nodeCount      = fromSnap.nodeCount;

        var newerImg: SystemImage;
        newerImg.generatedAt    = toSnap.timestamp;
        newerImg.globalHealth   = toSnap.globalHealth;
        newerImg.globalRisk     = toSnap.globalRisk;
        newerImg.totalWeakPoints= toSnap.totalWeakPoints;
        newerImg.totalCritical  = toSnap.totalCritical;
        newerImg.reposScanned   = toSnap.reposScanned;
        newerImg.nodeCount      = toSnap.nodeCount;

        // Load per-node data if image files are available (written by takeSnapshot).
        // Older snapshots written before this feature won't have imagePath set — the
        // diff will still work with summary-only data, just no per-node breakdown.
        if fromSnap.imagePath != "" {
            const olderNodes = loadImageNodes(fromSnap.imagePath);
            if olderNodes.size > 0 {
                olderImg.nodes = olderNodes;
                if !quiet then
                    writeln("mass-panic diff: loaded ", olderNodes.size,
                            " nodes from ", fromSnap.id);
            }
        }
        if toSnap.imagePath != "" {
            const newerNodes = loadImageNodes(toSnap.imagePath);
            if newerNodes.size > 0 {
                newerImg.nodes = newerNodes;
                if !quiet then
                    writeln("mass-panic diff: loaded ", newerNodes.size,
                            " nodes from ", toSnap.id);
            }
        }

        const diff = diffSnapshots(olderImg, newerImg, fromSnap.tag, toSnap.tag);

        // Output
        if diffOutput != "" {
            try {
                var f = open(diffOutput, ioMode.cw);
                var w = f.writer(locking=false);
                writeDiffJson(w, diff);
                if !quiet then
                    writeln("mass-panic diff: wrote ", diffOutput);
            } catch e: Error {
                writeln("mass-panic diff: cannot write output: ", e.message());
            }
        } else {
            printDiff(diff, fromSnap, toSnap);
        }
    }

    proc printDiff(diff: TemporalDiff, from: TemporalSnapshot, to: TemporalSnapshot) {
        const arrow = if diff.healthDelta >= 0 then "▲" else "▼";
        writeln();
        writeln("=== MASS-PANIC TEMPORAL DIFF ===");
        writeln("From: ", from.id,
                if from.tag != "" then " (" + from.tag + ")" else "",
                "  ", from.timestamp);
        writeln("To:   ", to.id,
                if to.tag != "" then " (" + to.tag + ")" else "",
                "  ", to.timestamp);
        writeln();
        writeln("Health:      ", arrow, " ", formatDelta(diff.healthDelta * 100.0), "%");
        writeln("Risk:        ", if diff.riskDelta <= 0 then "▼" else "▲",
                " ", formatDelta(diff.riskDelta * 100.0), "%");
        writeln("Weak points: ", formatDeltaInt(diff.weakPointDelta));
        writeln("Critical:    ", formatDeltaInt(diff.criticalDelta));
        if diff.newNodes.size > 0 then
            writeln("New repos:   +", diff.newNodes.size);
        if diff.removedNodes.size > 0 then
            writeln("Gone repos:  -", diff.removedNodes.size);

        // Per-node breakdown (only populated when full image files are available)
        if diff.improvedNodes.size > 0 {
            writeln("Improved:    ", diff.improvedNodes.size, " repos");
            for delta in diff.improvedNodes {
                writeln("  ▲ ", delta.name,
                        "  health ", formatDelta(delta.healthAfter - delta.healthBefore),
                        "  wp ", formatDeltaInt(delta.weakPointsAfter - delta.weakPointsBefore));
            }
        }
        if diff.degradedNodes.size > 0 {
            writeln("Degraded:    ", diff.degradedNodes.size, " repos");
            for delta in diff.degradedNodes {
                writeln("  ▼ ", delta.name,
                        "  health ", formatDelta(delta.healthAfter - delta.healthBefore),
                        "  wp ", formatDeltaInt(delta.weakPointsAfter - delta.weakPointsBefore));
            }
        }
        if diff.improvedNodes.size == 0 && diff.degradedNodes.size == 0 &&
           diff.unchangedCount == 0 {
            writeln("(run two scans to enable per-repo breakdown)");
        }
        writeln();
    }

    proc writeDiffJson(writer, diff: TemporalDiff) throws {
        writer.writeln("{");
        writer.writeln("  \"format\": \"", diff.format, "\",");
        writer.writeln("  \"from_timestamp\": \"", diff.fromTimestamp, "\",");
        writer.writeln("  \"to_timestamp\": \"", diff.toTimestamp, "\",");
        writer.writeln("  \"from_label\": \"", diff.fromLabel, "\",");
        writer.writeln("  \"to_label\": \"", diff.toLabel, "\",");
        writer.writeln("  \"health_delta\": ", diff.healthDelta, ",");
        writer.writeln("  \"risk_delta\": ", diff.riskDelta, ",");
        writer.writeln("  \"weak_point_delta\": ", diff.weakPointDelta, ",");
        writer.writeln("  \"critical_delta\": ", diff.criticalDelta, ",");
        writer.writeln("  \"new_repos\": ", diff.newNodes.size, ",");
        writer.writeln("  \"removed_repos\": ", diff.removedNodes.size, ",");
        writer.writeln("  \"improved_repos\": ", diff.improvedNodes.size, ",");
        writer.writeln("  \"degraded_repos\": ", diff.degradedNodes.size, ",");
        writer.writeln("  \"unchanged_repos\": ", diff.unchangedCount, ",");

        // Per-node deltas — empty arrays when image files were not available
        writer.writeln("  \"improved\": [");
        for (delta, idx) in zip(diff.improvedNodes, 0..) {
            if idx > 0 then writer.write(", ");
            writer.write("{\"id\": \"", delta.nodeId, "\", \"name\": \"", delta.name, "\", ");
            writer.write("\"health_before\": ", delta.healthBefore, ", ");
            writer.write("\"health_after\": ", delta.healthAfter, ", ");
            writer.write("\"wp_before\": ", delta.weakPointsBefore, ", ");
            writer.write("\"wp_after\": ", delta.weakPointsAfter, "}");
        }
        writer.writeln("\n  ],");

        writer.writeln("  \"degraded\": [");
        for (delta, idx) in zip(diff.degradedNodes, 0..) {
            if idx > 0 then writer.write(", ");
            writer.write("{\"id\": \"", delta.nodeId, "\", \"name\": \"", delta.name, "\", ");
            writer.write("\"health_before\": ", delta.healthBefore, ", ");
            writer.write("\"health_after\": ", delta.healthAfter, ", ");
            writer.write("\"wp_before\": ", delta.weakPointsBefore, ", ");
            writer.write("\"wp_after\": ", delta.weakPointsAfter, "}");
        }
        writer.writeln("\n  ]");

        writer.writeln("}");
    }

    proc formatDelta(v: real): string {
        const s = (abs(v)):string;
        return if v > 0 then "+" + s else if v < 0 then "-" + s else "0";
    }

    proc formatDeltaInt(v: int): string {
        return if v > 0 then "+" + v:string else v:string;
    }

    // ---------------------------------------------------------------------------
    // Repository discovery
    // ---------------------------------------------------------------------------

    proc discoverRepos(): list(string) {
        var repos: list(string);

        if repoManifest != "" {
            // Load from manifest file (one repo path per line)
            try {
                var f = open(repoManifest, ioMode.r);
                var reader = f.reader(locking=false);
                var line: string;
                while reader.readLine(line, stripNewline=true) {
                    const trimmed = line.strip();
                    if trimmed != "" && !trimmed.startsWith("#") {
                        repos.pushBack(trimmed);
                    }
                }
            } catch e: Error {
                writeln("mass-panic: cannot read manifest ", repoManifest, ": ", e.message());
            }
        } else if repoDirectory != "" {
            // Walk directory for .git subdirectories
            for entry in listDir(repoDirectory, dirs=true, files=false) {
                const fullPath = joinPath(repoDirectory, entry);
                const gitDir = joinPath(fullPath, ".git");
                if safeIsDir(gitDir) {
                    repos.pushBack(fullPath);
                }
            }
        } else {
            writeln("mass-panic: provide --repoManifest or --repoDirectory");
        }

        return repos;
    }

    // ---------------------------------------------------------------------------
    // Per-repo scanning via panic-attack binary
    // ---------------------------------------------------------------------------

    proc scanRepo(repoPath: string, cache: FingerprintCache): RepoResult {
        var result: RepoResult;
        result.repoPath = repoPath;
        result.repoName = basename(repoPath);

        // Incremental: check BLAKE3 fingerprint against cache
        if incremental && cache.has(repoPath) {
            var currentFp = computeFingerprint(repoPath);
            if currentFp == cache.get(repoPath) {
                result.skipped = true;
                result.fingerprint = currentFp;
                return result;
            }
        }

        // Build command arguments based on mode
        var cmdArgs = buildCommandArgs(repoPath);

        // Invoke panic-attack with mode-specific arguments
        try {
            var sub = spawn(
                cmdArgs.toArray(),
                stdout=pipeStyle.pipe,
                stderr=pipeStyle.pipe
            );

            var jsonOutput: string;
            var line: string;
            while sub.stdout.readLine(line, stripNewline=true) {
                jsonOutput += line + "\n";
            }
            sub.wait();

            if sub.exitCode == 0 {
                result = parseRepoResult(jsonOutput, repoPath);
                result.fingerprint = computeFingerprint(repoPath);
            } else {
                var errLine: string;
                var errOutput: string;
                while sub.stderr.readLine(errLine, stripNewline=true) {
                    errOutput += errLine + "\n";
                }
                result.error = "exit code " + sub.exitCode:string + ": " + errOutput;
            }

            // If mode is "full" or "assault", run additional passes and
            // fold crash counts back into the result
            if sub.exitCode == 0 && (mode == "full" || mode == "assault") {
                const attackCrashes = runAttackPass(repoPath);
                result.crashes += attackCrashes;
                result.weakPointCount += attackCrashes;
            }
            if sub.exitCode == 0 && (mode == "full" || mode == "adjudicate") {
                const adjResult = runAdjudicatePass(repoPath);
                result.crashes += adjResult.crashes;
                result.weakPointCount += adjResult.crashes;
                if adjResult.verdict != "" then
                    result.verdict = adjResult.verdict;
            }
        } catch e: Error {
            result.error = "spawn error: " + e.message();
        }

        return result;
    }

    // ---------------------------------------------------------------------------
    // Fingerprint computation (calls panic-attack or uses BLAKE3 directly)
    // ---------------------------------------------------------------------------

    proc computeFingerprint(repoPath: string): string {
        // Shell out to panic-attack for BLAKE3 fingerprint consistency
        try {
            var sub = spawn(
                [panicAttackBin, "fingerprint", repoPath],
                stdout=pipeStyle.pipe,
                stderr=pipeStyle.close
            );
            var fp: string;
            sub.stdout.readLine(fp, stripNewline=true);
            sub.wait();
            if sub.exitCode == 0 then return fp.strip();
        } catch { }

        // Fallback: use BLAKE3 via shell
        try {
            var sub = spawn(
                ["b3sum", "--no-names", repoPath],
                stdout=pipeStyle.pipe,
                stderr=pipeStyle.close
            );
            var fp: string;
            sub.stdout.readLine(fp, stripNewline=true);
            sub.wait();
            if sub.exitCode == 0 then return fp.strip();
        } catch { }

        return "";
    }

    // ---------------------------------------------------------------------------
    // Multi-mode command building
    // ---------------------------------------------------------------------------

    /// Build the panic-attack command arguments for the selected mode.
    proc buildCommandArgs(repoPath: string): list(string) {
        var args: list(string);
        args.pushBack(panicAttackBin);

        select mode {
            when "assail" {
                // --quiet causes assail to emit JSON on stdout (no --output needed)
                args.pushBack("--quiet");
                args.pushBack("assail");
                args.pushBack(repoPath);
            }
            when "assault" {
                // Full stress test: assail + attack all axes
                args.pushBack("--quiet");
                args.pushBack("assault");
                args.pushBack(repoPath);
                args.pushBack("--output-format=json");
                args.pushBack("--timeout=" + attackTimeout:string);
                if attackAxes != "all" {
                    for axis in attackAxes.split(",") {
                        args.pushBack("--axis=" + axis.strip());
                    }
                }
            }
            when "ambush" {
                // Timeline-driven stress test
                args.pushBack("--quiet");
                args.pushBack("ambush");
                args.pushBack(repoPath);
                args.pushBack("--output-format=json");
                args.pushBack("--intensity=" + intensity);
            }
            when "adjudicate" {
                // Logic-based verdict (needs prior reports)
                args.pushBack("assail");
                args.pushBack(repoPath);
                args.pushBack("--output-format=json");
            }
            when "full" {
                // Start with assail, then follow up with attack + adjudicate
                args.pushBack("assail");
                args.pushBack(repoPath);
                args.pushBack("--output-format=json");
            }
            otherwise {
                writeln("mass-panic: unknown mode '", mode, "', defaulting to assail");
                args.pushBack("assail");
                args.pushBack(repoPath);
                args.pushBack("--output-format=json");
            }
        }

        if quiet then args.pushBack("--quiet");

        return args;
    }

    /// Run attack pass on a repo (for assault/full modes).
    /// Spawns panic-attack attack with configured axes and timeout.
    /// Returns the number of crashes detected in the attack JSON output.
    proc runAttackPass(repoPath: string): int {
        try {
            var args: list(string);
            args.pushBack(panicAttackBin);
            args.pushBack("attack");
            args.pushBack(repoPath);
            args.pushBack("--output-format=json");
            args.pushBack("--timeout=" + attackTimeout:string);
            if quiet then args.pushBack("--quiet");

            if attackAxes != "all" {
                for axis in attackAxes.split(",") {
                    args.pushBack("--axis=" + axis.strip());
                }
            }

            var sub = spawn(
                args.toArray(),
                stdout=pipeStyle.pipe,
                stderr=pipeStyle.close
            );

            var jsonOutput: string;
            var line: string;
            while sub.stdout.readLine(line, stripNewline=true) {
                jsonOutput += line + "\n";
            }
            sub.wait();

            if sub.exitCode == 0 {
                // Extract crash counts from attack JSON output.
                // Attack output contains "crashes": N or "crash_count": N
                var crashes = extractInt(jsonOutput, "\"crashes\":");
                if crashes == 0 then
                    crashes = extractInt(jsonOutput, "\"crash_count\":");
                return crashes;
            }
        } catch { }

        return 0;
    }

    // Intermediate record for adjudicate pass results
    record AdjudicateResult {
        var crashes: int = 0;
        var verdict: string = "";
    }

    /// Run adjudicate pass on a repo (for adjudicate/full modes).
    /// Spawns panic-attack adjudicate to produce miniKanren verdict.
    /// Returns crash count and verdict string parsed from JSON output.
    proc runAdjudicatePass(repoPath: string): AdjudicateResult {
        var adjResult: AdjudicateResult;
        try {
            var sub = spawn(
                [panicAttackBin, "adjudicate", repoPath,
                 "--output-format=json"],
                stdout=pipeStyle.pipe,
                stderr=pipeStyle.close
            );

            var jsonOutput: string;
            var line: string;
            while sub.stdout.readLine(line, stripNewline=true) {
                jsonOutput += line + "\n";
            }
            sub.wait();

            if sub.exitCode == 0 {
                // Extract crash count from adjudicate JSON
                adjResult.crashes = extractInt(jsonOutput, "\"crashes\":");
                if adjResult.crashes == 0 then
                    adjResult.crashes = extractInt(jsonOutput, "\"crash_count\":");

                // Extract verdict string: "verdict":"pass" or "verdict":"fail" etc.
                adjResult.verdict = extractQuotedString(jsonOutput, "\"verdict\":");
            }
        } catch { }

        return adjResult;
    }

    // ---------------------------------------------------------------------------
    // Output writing
    // ---------------------------------------------------------------------------

    proc writeOutputs(report: AssemblylineReport, image: SystemImage,
                      results: [] RepoResult) {
        try {
            mkdir(outputDir, parents=true);
        } catch { }

        const timestamp = dateString();

        // Write assemblyline report
        const reportPath = joinPath(outputDir, "assemblyline-" + timestamp + ".json");
        try {
            var f = open(reportPath, ioMode.cw);
            var w = f.writer(locking=false);
            writeAssemblylineJson(w, report);
        } catch e: Error {
            writeln("mass-panic: cannot write report: ", e.message());
        }

        // Write system image
        var imgPath = imagingOutput;
        if imgPath == "" then
            imgPath = joinPath(outputDir, "system-image-" + timestamp + ".json");
        try {
            var f = open(imgPath, ioMode.cw);
            var w = f.writer(locking=false);
            writeSystemImageJson(w, image);
        } catch e: Error {
            writeln("mass-panic: cannot write image: ", e.message());
        }

        // Write PanLL export if enabled
        if panllExport {
            const panllPath = joinPath(outputDir, "system-image-" + timestamp + ".panll.json");
            try {
                var sub = spawn(
                    [panicAttackBin, "image", "--panll",
                     "--output=" + imgPath,
                     "--quiet", repoDirectory],
                    stdout=pipeStyle.close,
                    stderr=pipeStyle.close
                );
                sub.wait();
            } catch { }
        }

        // Generate notification if enabled
        if notify {
            try {
                var notifyArgs: list(string);
                notifyArgs.pushBack(panicAttackBin);
                notifyArgs.pushBack("notify");
                notifyArgs.pushBack(reportPath);
                if notifyCriticalOnly then
                    notifyArgs.pushBack("--critical-only");
                notifyArgs.pushBack("--output=" + joinPath(outputDir, "notification-" + timestamp + ".md"));

                var sub = spawn(
                    notifyArgs.toArray(),
                    stdout=pipeStyle.close,
                    stderr=pipeStyle.close
                );
                sub.wait();
            } catch { }
        }

        if !quiet then
            writeln("mass-panic: wrote ", reportPath, " and ", imgPath);
    }

    // ---------------------------------------------------------------------------
    // Summary printing
    // ---------------------------------------------------------------------------

    proc printSummary(report: AssemblylineReport, image: SystemImage) {
        writeln();
        writeln("=== MASS-PANIC SUMMARY (mode: ", mode, ") ===");
        writeln("Locales: ", numLocales,
                "  |  Repos scanned: ", report.reposScanned,
                "  |  Skipped: ", report.reposSkipped,
                "  |  With findings: ", report.reposWithFindings);
        writeln("Total weak points: ", report.totalWeakPoints,
                "  |  Critical: ", report.totalCritical);
        writeln("System health: ", formatPercent(image.globalHealth),
                "  |  Risk intensity: ", formatPercent(image.globalRisk));
        writeln("Image nodes: ", image.nodeCount,
                "  |  Edges: ", image.edgeCount);
        writeln();
    }

    proc formatPercent(v: real): string {
        return (v * 100.0):string + "%";
    }

    proc dateString(): string {
        // ISO-8601 timestamp via system date command (sortable, human-readable)
        try {
            var sub = spawn(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                            stdout=pipeStyle.pipe,
                            stderr=pipeStyle.close);
            var result: string;
            sub.stdout.readLine(result, stripNewline=true);
            sub.wait();
            if sub.exitCode == 0 then return result.strip();
        } catch { }
        // Fallback: epoch seconds (always available)
        return timeSinceEpoch().totalSeconds(): int: string;
    }

    // ---------------------------------------------------------------------------
    // Result sorting comparator
    // ---------------------------------------------------------------------------

    record ResultComparator: relativeComparator {
        proc compare(a: RepoResult, b: RepoResult): int {
            // Descending by weak point count
            return b.weakPointCount - a.weakPointCount;
        }
    }
}
