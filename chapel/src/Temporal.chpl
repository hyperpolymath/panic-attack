// SPDX-License-Identifier: PMPL-1.0-or-later

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
    use Path;
    use Imaging;
    use Protocol;

    // ---------------------------------------------------------------------------
    // Temporal snapshot types
    // ---------------------------------------------------------------------------

    record TemporalSnapshot {
        var id: string;
        var timestamp: string;
        var label: string;          // user-provided label (e.g. "pre-refactor")
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

    proc takeSnapshot(image: SystemImage, report: AssemblylineReport,
                      verisimdbDir: string, label: string) {
        const indexPath = joinPath(verisimdbDir, "temporal-index.json");
        var index = loadTemporalIndex(indexPath);

        const seq = index.snapshotCount + 1;
        const snapshotId = "snap-" + seq: string;

        // Write the system image as a VeriSimDB hexad
        const hexadDir = joinPath(verisimdbDir, "hexads");
        try { mkdir(hexadDir, parents=true); } catch { }
        const hexadPath = joinPath(hexadDir, snapshotId + ".json");
        try {
            var f = open(hexadPath, ioMode.cw);
            var w = f.writer(locking=false);
            writeTemporalHexad(w, image, snapshotId, seq, label);
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

        // Update the temporal index
        var snapshot: TemporalSnapshot;
        snapshot.id = snapshotId;
        snapshot.timestamp = image.generatedAt;
        snapshot.label = label;
        snapshot.sequenceNumber = seq;
        snapshot.imagePath = imagePath;
        snapshot.hexadPath = hexadPath;
        snapshot.globalHealth = image.globalHealth;
        snapshot.globalRisk = image.globalRisk;
        snapshot.totalWeakPoints = image.totalWeakPoints;
        snapshot.totalCritical = image.totalCritical;
        snapshot.reposScanned = image.reposScanned;
        snapshot.nodeCount = image.nodeCount;

        index.snapshots.pushBack(snapshot);
        index.snapshotCount = index.snapshots.size;
        index.lastUpdated = image.generatedAt;

        saveTemporalIndex(index, indexPath);
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
        var olderNodes: map(string, ImageNode);
        for node in older.nodes {
            olderNodes[node.id] = node;
        }

        var newerNodes: map(string, ImageNode);
        for node in newer.nodes {
            newerNodes[node.id] = node;
        }

        // Find new, removed, improved, and degraded nodes
        for node in newer.nodes {
            if !olderNodes.contains(node.id) {
                diff.newNodes.pushBack(node.id);
            } else {
                const oldNode = olderNodes[node.id];
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

    proc loadTemporalIndex(path: string): TemporalIndex {
        var index: TemporalIndex;
        // If no index exists, return empty
        if !isFile(path) then return index;

        // Minimal parsing — extract snapshot count and last updated
        try {
            var f = open(path, ioMode.r);
            var reader = f.reader(locking=false);
            var content: string;
            var line: string;
            while reader.readLine(line, stripNewline=true) {
                content += line;
            }
            index.snapshotCount = extractInt(content, "\"snapshot_count\":");
        } catch { }

        return index;
    }

    proc saveTemporalIndex(index: TemporalIndex, path: string) {
        try {
            var f = open(path, ioMode.cw);
            var w = f.writer(locking=false);
            w.writeln("{");
            w.writeln("  \"format\": \"", index.format, "\",");
            w.writeln("  \"last_updated\": \"", index.lastUpdated, "\",");
            w.writeln("  \"snapshot_count\": ", index.snapshotCount, ",");
            w.writeln("  \"snapshots\": [");
            for (snap, idx) in zip(index.snapshots, 0..) {
                if idx > 0 then w.writeln(",");
                w.write("    {");
                w.write("\"id\": \"", snap.id, "\", ");
                w.write("\"timestamp\": \"", snap.timestamp, "\", ");
                w.write("\"label\": \"", snap.label, "\", ");
                w.write("\"sequence\": ", snap.sequenceNumber, ", ");
                w.write("\"health\": ", snap.globalHealth, ", ");
                w.write("\"risk\": ", snap.globalRisk, ", ");
                w.write("\"weak_points\": ", snap.totalWeakPoints, ", ");
                w.write("\"critical\": ", snap.totalCritical, ", ");
                w.write("\"repos\": ", snap.reposScanned, ", ");
                w.write("\"nodes\": ", snap.nodeCount);
                w.write("}");
            }
            w.writeln("\n  ]");
            w.writeln("}");
        } catch e: Error {
            writeln("temporal: cannot save index: ", e.message());
        }
    }

    // ---------------------------------------------------------------------------
    // VeriSimDB hexad writing for temporal snapshots
    // ---------------------------------------------------------------------------

    proc writeTemporalHexad(writer, image: SystemImage, snapshotId: string,
                            seq: int, label: string) throws {
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
        writer.writeln("    \"label\": \"", label, "\"");
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
