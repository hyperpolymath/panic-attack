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

    // ---------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------

    proc main() {
        // Route to diff subcommand before doing any scanning
        if subcommand == "diff" {
            runDiff();
            return;
        }

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

        // Collect and sort results
        const actualCount = resultIdx.read();
        var results = allResults[0..#actualCount];
        sort(results, comparator=new ResultComparator());

        // Filter to only repos with findings if --findingsOnly
        var filteredResults = results;
        if findingsOnly {
            var kept: list(RepoResult);
            for r in results {
                if r.weakPointCount > 0 || r.error != "" then
                    kept.pushBack(r);
            }
            filteredResults = kept.toArray();
        }

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

        // Build minimal SystemImage objects from snapshot summaries —
        // global metrics are accurate; per-node breakdown is not available
        // without loading the full image JSON.
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
        if diff.improvedNodes.size > 0 then
            writeln("Improved:    ", diff.improvedNodes.size, " repos");
        if diff.degradedNodes.size > 0 then
            writeln("Degraded:    ", diff.degradedNodes.size, " repos");
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
        writer.writeln("  \"unchanged_repos\": ", diff.unchangedCount);
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
                args.pushBack("assail");
                args.pushBack(repoPath);
                args.pushBack("--output-format=json");
            }
            when "assault" {
                // Full stress test: assail + attack all axes
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
