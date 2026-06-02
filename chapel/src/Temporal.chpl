// SPDX-License-Identifier: MPL-2.0

//
// Temporal — time-series navigation through system health snapshots.
//
// Every mass-panic scan produces a SystemImage. This module stores those
// images as VeriSimDB hexads with temporal facets, creating a navigable
// timeline of system health. Users can:
//
//   1. Move forward/backward through scan history
//   2. Diff any two points in time to see what changed
//   3. Identify trends (improving, degrading, oscillating)
//   4. Compute the impact of code changes on system health
//   5. Replay the evolution of a codebase's risk profile
//
// Storage: Each snapshot is a VeriSimDB hexad with six facets:
//   - document:   Full SystemImage JSON
//   - semantic:   Extracted health metrics and risk distribution
//   - temporal:   ISO 8601 timestamp, scan duration, sequence number
//   - structural: Node/edge topology summary
//   - provenance: Scanner version, locale count, Chapel/Rust version
//   - identity:   BLAKE3 hash of the image content
//
// The temporal index itself is a lightweight JSON manifest listing all
// snapshots in chronological order, enabling O(1) time navigation.
//

module Temporal {
    use IO;
    use FileSystem;
    use List;
    use Map;
    use Path;
    use Imaging;
    use Protocol;

    // ---------------------------------------------------------------------------
    // Temporal snapshot types
    // ---------------------------------------------------------------------------

    record TemporalSnapshot {
        var id: string;
        var timestamp: string;
        var tag: string;          // user-provided label (e.g. "pre-refactor")
        var sequenceNumber: int;
        var imagePath: string;      // path to SystemImage JSON
        var hexadPath: string;      // path to VeriSimDB hexad

        // Summary metrics for fast timeline browsing without loading full images
        var globalHealth: real;
        var globalRisk: real;
        var totalWeakPoints: int;
        var totalCritical: int;
        var reposScanned: int;
        var nodeCount: int;
    }

    record TemporalIndex {
        var format: string = "panic-attack.temporal-index.v1";
        var createdAt: string;
        var lastUpdated: string;
        var snapshotCount: int;
        var snapshots: list(TemporalSnapshot);
    }

    record TemporalDiff {
        var format: string = "panic-attack.temporal-diff.v1";
        var fromTimestamp: string;
        var toTimestamp: string;
        var fromLabel: string;
        var toLabel: string;

        // Delta metrics
        var healthDelta: real;      // positive = improved
        var riskDelta: real;        // negative = improved
        var weakPointDelta: int;    // negative = improved
        var criticalDelta: int;     // negative = improved

        // Per-node changes
        var newNodes: list(string);       // repos added since 'from'
        var removedNodes: list(string);   // repos removed since 'from'
        var improvedNodes: list(NodeDelta);
        var degradedNodes: list(NodeDelta);
        var unchangedCount: int;
    }

    record NodeDelta {
        var nodeId: string;
        var name: string;
        var healthBefore: real;
        var healthAfter: real;
        var riskBefore: real;
        var riskAfter: real;
        var weakPointsBefore: int;
        var weakPointsAfter: int;
    }

    // ---------------------------------------------------------------------------
    // Snapshot management
    // ---------------------------------------------------------------------------

    // Default no-HTTP-push behaviour; overload with verisimPushUrl below
    // pushes via `panic-attack verisim-push` after each hexad write.
    proc takeSnapshot(image: SystemImage, report: AssemblylineReport,
                      verisimdbDir: string, snapTag: string) {
        takeSnapshot(image, report, verisimdbDir, snapTag,
                     verisimPushUrl="", panicAttackBin="");
    }

    // Take a snapshot AND, when `verisimPushUrl` is non-empty, push the
    // emitted hexad to the URL via `<panicAttackBin> verisim-push`.
    // Closes the v3.0.0 ROADMAP item "VeriSimDB HTTP push from Chapel
    // metalayer (currently file-only)".
    //
    // `panicAttackBin` defaults to `panic-attack` (assumed on PATH); set
    // it explicitly when running from `chapel/` without the binary on
    // PATH or against a non-installed build.
    //
    // The local filesystem write happens UNCONDITIONALLY — the push is
    // additive, not a replacement. If the push fails (HTTP unreachable,
    // verisim-panic-api not up, etc.), takeSnapshot's local writes
    // remain authoritative.
    proc takeSnapshot(image: SystemImage, report: AssemblylineReport,
                      verisimdbDir: string, snapTag: string,
                      verisimPushUrl: string,
                      panicAttackBin: string = "panic-attack") {
        const indexPath = joinPath(verisimdbDir, "temporal-index.json");

        // Read existing state without losing prior entries
        const existingCount = loadSnapshotCount(indexPath);
        const existingEntries = loadRawSnapshots(indexPath);

        const seq = existingCount + 1;
        const snapshotId = "snap-" + seq: string;

        // Write the system image as a VeriSimDB hexad
        const hexadDir = joinPath(verisimdbDir, "hexads");
        try { mkdir(hexadDir, parents=true); } catch { }
        const hexadPath = joinPath(hexadDir, snapshotId + ".json");
        try {
            var f = open(hexadPath, ioMode.cw);
            var w = f.writer(locking=false);
            writeTemporalHexad(w, image, snapshotId, seq, snapTag);
        } catch e: Error {
            writeln("temporal: cannot write hexad: ", e.message());
            return;
        }

        // Also write the raw image for direct access
        const imagesDir = joinPath(verisimdbDir, "images");
        try { mkdir(imagesDir, parents=true); } catch { }
        const imagePath = joinPath(imagesDir, snapshotId + "-image.json");
        try {
            var f = open(imagePath, ioMode.cw);
            var w = f.writer(locking=false);
            writeSystemImageJson(w, image);
        } catch e: Error {
            writeln("temporal: cannot write image: ", e.message());
        }

        // Build the new snapshot entry
        var snapshot: TemporalSnapshot;
        snapshot.id = snapshotId;
        snapshot.timestamp = image.generatedAt;
        snapshot.tag = snapTag;
        snapshot.sequenceNumber = seq;
        snapshot.imagePath = imagePath;
        snapshot.hexadPath = hexadPath;
        snapshot.globalHealth = image.globalHealth;
        snapshot.globalRisk = image.globalRisk;
        snapshot.totalWeakPoints = image.totalWeakPoints;
        snapshot.totalCritical = image.totalCritical;
        snapshot.reposScanned = image.reposScanned;
        snapshot.nodeCount = image.nodeCount;

        // Write index, preserving all existing entries
        saveTemporalIndex(indexPath, existingEntries, snapshot, seq);

        // Optional HTTP push: hand off the just-written hexad file to
        // `panic-attack verisim-push` so a running verisim-panic-api
        // gateway picks it up. The local filesystem write above is
        // unconditional and authoritative; the push is additive.
        // Closes v3.0.0 ROADMAP item "VeriSimDB HTTP push from Chapel
        // metalayer (currently file-only)".
        if verisimPushUrl != "" && panicAttackBin != "" {
            try {
                use Subprocess;
                var cmd = [
                    panicAttackBin,
                    "verisim-push",
                    "--url", verisimPushUrl,
                    "--retry",
                    hexadPath,
                ];
                var sub = spawn(cmd);
                sub.wait();
                if sub.exitCode != 0 {
                    writeln("temporal: verisim-push exited ", sub.exitCode,
                            " for ", hexadPath, " (local write OK)");
                }
            } catch e: Error {
                writeln("temporal: verisim-push not invoked: ", e.message(),
                        " (local write OK)");
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Temporal diff — compare two points in time
    // ---------------------------------------------------------------------------

    proc diffSnapshots(older: SystemImage, newer: SystemImage,
                       olderLabel: string, newerLabel: string): TemporalDiff {
        var diff: TemporalDiff;
        diff.fromTimestamp = older.generatedAt;
        diff.toTimestamp = newer.generatedAt;
        diff.fromLabel = olderLabel;
        diff.toLabel = newerLabel;

        diff.healthDelta = newer.globalHealth - older.globalHealth;
        diff.riskDelta = newer.globalRisk - older.globalRisk;
        diff.weakPointDelta = newer.totalWeakPoints - older.totalWeakPoints;
        diff.criticalDelta = newer.totalCritical - older.totalCritical;

        // Build lookup maps for node comparison
        var olderNodes = new map(string, ImageNode);
        for node in older.nodes {
            olderNodes[node.id] = node;
        }

        var newerNodes = new map(string, ImageNode);
        for node in newer.nodes {
            newerNodes[node.id] = node;
        }

        // Find new, removed, improved, and degraded nodes
        for node in newer.nodes {
            if !olderNodes.contains(node.id) {
                diff.newNodes.pushBack(node.id);
            } else {
                const oldNode = try! olderNodes[node.id];
                if node.skipped || oldNode.skipped then continue;

                const healthChange = node.healthScore - oldNode.healthScore;
                const threshold = 0.01;

                if abs(healthChange) < threshold {
                    diff.unchangedCount += 1;
                } else {
                    var delta: NodeDelta;
                    delta.nodeId = node.id;
                    delta.name = node.name;
                    delta.healthBefore = oldNode.healthScore;
                    delta.healthAfter = node.healthScore;
                    delta.riskBefore = oldNode.riskIntensity;
                    delta.riskAfter = node.riskIntensity;
                    delta.weakPointsBefore = oldNode.weakPointCount;
                    delta.weakPointsAfter = node.weakPointCount;

                    if healthChange > 0 then
                        diff.improvedNodes.pushBack(delta);
                    else
                        diff.degradedNodes.pushBack(delta);
                }
            }
        }

        for node in older.nodes {
            if !newerNodes.contains(node.id) {
                diff.removedNodes.pushBack(node.id);
            }
        }

        return diff;
    }

    // ---------------------------------------------------------------------------
    // Temporal index I/O
    // ---------------------------------------------------------------------------

    // Parse all snapshot summary entries from the temporal index.
    // Returns a list of TemporalSnapshot records with key metrics populated.
    // saveTemporalIndex writes each entry as a single line: "    {...}\n"
    // so we process line-by-line — no positional string arithmetic needed.
    proc loadSnapshotSummaries(path: string): list(TemporalSnapshot) {
        var results: list(TemporalSnapshot);
        if !safeIsFile(path) then return results;

        var inSnapshots = false;
        try {
            var f = open(path, ioMode.r);
            var reader = f.reader(locking=false);
            var line: string;
            while reader.readLine(line, stripNewline=true) {
                const trimmed = line.strip();

                // Enter/exit the snapshots array based on surrounding context
                if trimmed.startsWith("\"snapshots\": [") {
                    inSnapshots = true;
                    continue;
                }
                if inSnapshots && trimmed == "]" {
                    inSnapshots = false;
                    continue;
                }

                if !inSnapshots then continue;

                // Each non-empty, non-bracket line inside "snapshots" is one entry
                if trimmed == "" || trimmed == "[" || trimmed == "]" ||
                   trimmed == "," then continue;

                // Strip trailing comma if present (from the write loop)
                var obj = if trimmed.endsWith(",") then trimmed[..trimmed.size - 2] else trimmed;

                if !obj.startsWith("{") then continue;

                var snap: TemporalSnapshot;
                snap.id              = extractQuotedString(obj, "\"id\":");
                snap.timestamp       = extractQuotedString(obj, "\"timestamp\":");
                snap.tag             = extractQuotedString(obj, "\"label\":");
                snap.sequenceNumber  = extractInt(obj, "\"sequence\":");
                snap.globalHealth    = extractReal(obj, "\"health\":");
                snap.globalRisk      = extractReal(obj, "\"risk\":");
                snap.totalWeakPoints = extractInt(obj, "\"weak_points\":");
                snap.totalCritical   = extractInt(obj, "\"critical\":");
                snap.reposScanned    = extractInt(obj, "\"repos\":");
                snap.nodeCount       = extractInt(obj, "\"nodes\":");
                snap.imagePath       = extractQuotedString(obj, "\"image_path\":");

                if snap.id != "" then results.pushBack(snap);
            }
        } catch { }

        return results;
    }

    // ---------------------------------------------------------------------------
    // Full image node loading — enables per-node diff
    // ---------------------------------------------------------------------------

    // Load the node list from a saved SystemImage JSON file.
    // The image JSON contains a "nodes" array where each entry is a single-line
    // JSON object as written by writeNodeJson in Imaging.chpl.
    // Returns an empty list if the file is missing, unreadable, or has no nodes.
    proc loadImageNodes(imagePath: string): list(ImageNode) {
        var nodes: list(ImageNode);
        if imagePath == "" || !safeIsFile(imagePath) then return nodes;

        var inNodes = false;
        try {
            var f = open(imagePath, ioMode.r);
            var reader = f.reader(locking=false);
            var line: string;
            while reader.readLine(line, stripNewline=true) {
                const trimmed = line.strip();

                if trimmed.startsWith("\"nodes\"") {
                    inNodes = true;
                    continue;
                }
                // The edges array follows nodes — stop when we hit it
                if inNodes && trimmed.startsWith("\"edges\"") {
                    break;
                }
                if inNodes && trimmed.startsWith("]") {
                    inNodes = false;
                    continue;
                }

                if !inNodes then continue;
                if trimmed == "" || trimmed == "[" then continue;

                // Strip trailing comma if present
                var obj = if trimmed.endsWith(",") then trimmed[..trimmed.size - 2] else trimmed;
                if !obj.startsWith("{") then continue;

                var node: ImageNode;
                node.id             = extractQuotedString(obj, "\"id\":");
                node.name           = extractQuotedString(obj, "\"name\":");
                node.level          = extractQuotedString(obj, "\"level\":");
                node.healthScore    = extractReal(obj, "\"health_score\":");
                node.riskIntensity  = extractReal(obj, "\"risk_intensity\":");
                node.weakPointDensity = extractReal(obj, "\"weak_point_density\":");
                node.weakPointCount = extractInt(obj, "\"weak_point_count\":");
                node.criticalCount  = extractInt(obj, "\"critical_count\":");
                node.totalFiles     = extractInt(obj, "\"total_files\":");
                node.totalLines     = extractInt(obj, "\"total_lines\":");
                node.fingerprint    = extractQuotedString(obj, "\"fingerprint\":");
                // skipped is an unquoted boolean: scan for "skipped": true
                node.skipped = obj.find("\"skipped\": true") != -1 ||
                               obj.find("\"skipped\":true") != -1;

                if node.id != "" then nodes.pushBack(node);
            }
        } catch { }

        return nodes;
    }

    // Extract a real (floating-point) value following a JSON key.
    proc extractReal(json: string, key: string): real {
        const idx = json.find(key);
        if idx == -1 then return 0.0;
        // Scan past the key then collect digits/dot — avoids byteIndex arithmetic
        var afterKey: string;
        try { afterKey = json[idx..]; } catch { return 0.0; }
        var skipped = 0;
        var numStr: string;
        var seenDot = false;
        for ch in afterKey {
            skipped += 1;
            if skipped <= key.size then continue;
            if (ch >= "0" && ch <= "9") || (ch == "." && !seenDot) {
                if ch == "." then seenDot = true;
                numStr += ch;
            } else if ch == "-" && numStr.size == 0 {
                numStr += ch;
            } else if numStr.size > 0 {
                break;
            }
        }
        if numStr.size > 0 {
            try { return numStr: real; } catch { return 0.0; }
        }
        return 0.0;
    }

    // Returns the current snapshot count by reading the on-disk index.
    // Does NOT attempt to parse the full snapshots array — we preserve those
    // as a raw string and splice the new entry in during save.
    proc loadSnapshotCount(path: string): int {
        if !safeIsFile(path) then return 0;
        try {
            var f = open(path, ioMode.r);
            var reader = f.reader(locking=false);
            var content: string;
            var line: string;
            while reader.readLine(line, stripNewline=true) {
                content += line;
            }
            return extractInt(content, "\"snapshot_count\":");
        } catch { }
        return 0;
    }

    // Read the raw snapshot entries from an existing temporal index.
    // Collects all lines between "snapshots": [ and the closing ], stripped of
    // the surrounding brackets, so they can be spliced into the new index file.
    proc loadRawSnapshots(path: string): string {
        if !safeIsFile(path) then return "";
        var collected: string;
        var inSnapshots = false;
        try {
            var f = open(path, ioMode.r);
            var reader = f.reader(locking=false);
            var line: string;
            while reader.readLine(line, stripNewline=true) {
                const trimmed = line.strip();
                if trimmed.startsWith("\"snapshots\": [") {
                    inSnapshots = true;
                    continue;
                }
                if inSnapshots && trimmed == "]" {
                    break;
                }
                if inSnapshots && trimmed != "" {
                    if collected != "" then collected += "\n";
                    collected += line;
                }
            }
        } catch { }
        return collected.strip();
    }

    // Write the temporal index to disk, preserving all existing snapshot entries
    // from the raw string plus appending the new entry.
    proc saveTemporalIndex(path: string, existingEntries: string,
                           newSnap: TemporalSnapshot, newCount: int) {
        try {
            var f = open(path, ioMode.cw);
            var w = f.writer(locking=false);
            w.writeln("{");
            w.writeln("  \"format\": \"panic-attack.temporal-index.v1\",");
            w.writeln("  \"last_updated\": \"", newSnap.timestamp, "\",");
            w.writeln("  \"snapshot_count\": ", newCount, ",");
            w.writeln("  \"snapshots\": [");

            // Splice in all prior entries followed by the new one
            if existingEntries != "" {
                w.writeln(existingEntries, ",");
            }

            // New snapshot entry — image_path enables per-node diff on reload
            w.write("    {");
            w.write("\"id\": \"", newSnap.id, "\", ");
            w.write("\"timestamp\": \"", newSnap.timestamp, "\", ");
            w.write("\"label\": \"", newSnap.tag, "\", ");
            w.write("\"sequence\": ", newSnap.sequenceNumber, ", ");
            w.write("\"health\": ", newSnap.globalHealth, ", ");
            w.write("\"risk\": ", newSnap.globalRisk, ", ");
            w.write("\"weak_points\": ", newSnap.totalWeakPoints, ", ");
            w.write("\"critical\": ", newSnap.totalCritical, ", ");
            w.write("\"repos\": ", newSnap.reposScanned, ", ");
            w.write("\"nodes\": ", newSnap.nodeCount, ", ");
            w.write("\"image_path\": \"", newSnap.imagePath, "\"");
            w.writeln("}");

            w.writeln("  ]");
            w.writeln("}");
        } catch e: Error {
            writeln("temporal: cannot save index: ", e.message());
        }
    }

    // ---------------------------------------------------------------------------
    // VeriSimDB hexad writing for temporal snapshots
    // ---------------------------------------------------------------------------

    proc writeTemporalHexad(writer, image: SystemImage, snapshotId: string,
                            seq: int, snapTag: string) throws {
        writer.writeln("{");
        writer.writeln("  \"schema\": \"verisimdb.hexad.v1\",");
        writer.writeln("  \"id\": \"", snapshotId, "\",");
        writer.writeln("  \"created_at\": \"", image.generatedAt, "\",");

        // Provenance facet
        writer.writeln("  \"provenance\": {");
        writer.writeln("    \"tool\": \"panic-attack-chapel\",");
        writer.writeln("    \"version\": \"", "2.2.0", "\",");
        writer.writeln("    \"locales\": ", numLocales, ",");
        writer.writeln("    \"scan_surface\": \"", image.scanSurface, "\"");
        writer.writeln("  },");

        // Temporal facet
        writer.writeln("  \"temporal\": {");
        writer.writeln("    \"timestamp\": \"", image.generatedAt, "\",");
        writer.writeln("    \"sequence_number\": ", seq, ",");
        writer.writeln("    \"label\": \"", snapTag, "\"");
        writer.writeln("  },");

        // Semantic facet
        writer.writeln("  \"semantic\": {");
        writer.writeln("    \"global_health\": ", image.globalHealth, ",");
        writer.writeln("    \"global_risk\": ", image.globalRisk, ",");
        writer.writeln("    \"total_weak_points\": ", image.totalWeakPoints, ",");
        writer.writeln("    \"total_critical\": ", image.totalCritical, ",");
        writer.writeln("    \"repos_scanned\": ", image.reposScanned, ",");
        writer.writeln("    \"node_count\": ", image.nodeCount, ",");
        writer.writeln("    \"edge_count\": ", image.edgeCount);
        writer.writeln("  },");

        // Structural facet (topology summary)
        writer.writeln("  \"structural\": {");
        writer.writeln("    \"total_files\": ", image.totalFiles, ",");
        writer.writeln("    \"total_lines\": ", image.totalLines, ",");
        writer.writeln("    \"risk_distribution\": {");
        writer.writeln("      \"healthy\": ", image.riskDistribution.healthy, ",");
        writer.writeln("      \"low\": ", image.riskDistribution.low, ",");
        writer.writeln("      \"moderate\": ", image.riskDistribution.moderate, ",");
        writer.writeln("      \"high\": ", image.riskDistribution.high, ",");
        writer.writeln("      \"critical\": ", image.riskDistribution.critical);
        writer.writeln("    }");
        writer.writeln("  }");

        writer.writeln("}");
    }
}
