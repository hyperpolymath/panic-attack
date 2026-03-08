// SPDX-License-Identifier: PMPL-1.0-or-later

//
// Imaging — fNIRS-inspired system health imaging for codebases.
//
// Concept: Just as fNIRS creates a spatial map of brain activity by measuring
// blood oxygenation across cortical regions in real-time, this module creates
// a spatial map of codebase health by measuring weak point density, risk
// intensity, and change velocity across the repository topology.
//
// The SystemImage is a point-in-time snapshot of the entire scanned surface.
// Multiple images over time create a temporal sequence that can be navigated
// forward and backward (via VeriSimDB), revealing how system health evolves
// and where problems concentrate, propagate, or resolve.
//
// Terminology mapping:
//   fNIRS term          → panic-attack equivalent
//   ──────────────        ───────────────────────
//   Cortical region     → Repository / directory / file
//   Blood oxygenation   → Health score (inverse of risk)
//   Neural activation   → Weak point density (findings per KLOC)
//   Hemodynamic response→ Change velocity (how fast risk is changing)
//   Optode placement    → Scanner coverage (which files were analyzed)
//   Channel             → Dependency / taint flow edge
//   Functional map      → SystemImage
//   Time series         → Temporal snapshot sequence in VeriSimDB
//

module Imaging {
    use IO;
    use List;
    use Map;
    use Sort;
    use Protocol;

    // ---------------------------------------------------------------------------
    // Core imaging types
    // ---------------------------------------------------------------------------

    // A SystemImage is the "functional scan" of an entire codebase at one instant.
    record SystemImage {
        var format: string = "panic-attack.system-image.v1";
        var generatedAt: string;
        var scanSurface: string;      // root directory or account name
        var nodeCount: int;
        var edgeCount: int;
        var globalHealth: real;       // 0.0 (critical) to 1.0 (healthy)
        var globalRisk: real;         // 0.0 (safe) to 1.0 (critical)
        var totalWeakPoints: int;
        var totalCritical: int;
        var totalLines: int;
        var totalFiles: int;
        var reposScanned: int;
        var localesUsed: int;

        // Per-repo image nodes (the "voxels" of the scan)
        var nodes: list(ImageNode);
        // Cross-repo edges (dependency flows, shared patterns)
        var edges: list(ImageEdge);
        // Risk distribution histogram
        var riskDistribution: RiskDistribution;
    }

    // An ImageNode is one "voxel" — a repository's health reading.
    // At finer granularity (future), nodes can represent directories or files.
    record ImageNode {
        var id: string;
        var path: string;
        var name: string;
        var level: string = "repository"; // repository | directory | file
        var healthScore: real;     // 0.0 = critical, 1.0 = healthy
        var riskIntensity: real;   // 0.0 = safe, 1.0 = critical
        var weakPointDensity: real; // findings per 1000 lines
        var weakPointCount: int;
        var criticalCount: int;
        var highCount: int;
        var totalFiles: int;
        var totalLines: int;
        var fingerprint: string;   // BLAKE3 for temporal diff
        var skipped: bool = false;
        var error: string = "";

        // Category breakdown — the "spectral channels" of the scan
        var categoryBreakdown: list(CategoryCount);
    }

    // An ImageEdge represents a relationship between two nodes.
    // In the fNIRS analogy, these are the "functional connectivity" channels.
    record ImageEdge {
        var fromNode: string;
        var toNode: string;
        var edgeType: string;  // "shared_pattern" | "common_dependency" | "risk_proximity"
        var weight: real;      // strength of relationship
    }

    // Risk distribution across the scan surface — like an fNIRS histogram
    // showing how many channels are at each activation level.
    record RiskDistribution {
        var healthy: int;     // risk < 0.2
        var low: int;         // 0.2 <= risk < 0.4
        var moderate: int;    // 0.4 <= risk < 0.6
        var high: int;        // 0.6 <= risk < 0.8
        var critical: int;    // risk >= 0.8
    }

    // ---------------------------------------------------------------------------
    // Image construction from scan results
    // ---------------------------------------------------------------------------

    proc buildSystemImage(results: [] RepoResult, totalRepos: int): SystemImage {
        var image: SystemImage;
        image.generatedAt = "";  // filled by caller
        image.reposScanned = totalRepos;
        image.localesUsed = numLocales;

        var totalWP = 0;
        var totalCrit = 0;
        var totalLines = 0;
        var totalFiles = 0;
        var healthSum = 0.0;
        var riskSum = 0.0;
        var nonSkippedCount = 0;

        for result in results {
            var node: ImageNode;
            node.id = "repo:" + result.repoName;
            node.path = result.repoPath;
            node.name = result.repoName;
            node.weakPointCount = result.weakPointCount;
            node.criticalCount = result.criticalCount;
            node.highCount = result.highCount;
            node.totalFiles = result.totalFiles;
            node.totalLines = result.totalLines;
            node.fingerprint = result.fingerprint;
            node.skipped = result.skipped;
            node.error = result.error;
            node.categoryBreakdown = result.categories;

            if !result.skipped && result.error == "" {
                // Compute risk intensity: weighted formula based on findings density
                const kloc = max(result.totalLines, 1): real / 1000.0;
                node.weakPointDensity = result.weakPointCount: real / kloc;

                // Risk intensity: critical findings weighted 3x, high 2x, others 1x
                const weightedScore = (result.criticalCount * 3 +
                                       result.highCount * 2 +
                                       max(result.weakPointCount - result.criticalCount -
                                           result.highCount, 0)): real;
                // Normalise against KLOC — a 100-line file with 5 findings is riskier
                // than a 10,000-line file with 5 findings
                const rawRisk = weightedScore / kloc;
                // Sigmoid squash to [0, 1] — asymptotically approaches 1.0
                node.riskIntensity = sigmoid(rawRisk, midpoint=5.0, steepness=0.5);
                node.healthScore = 1.0 - node.riskIntensity;

                healthSum += node.healthScore;
                riskSum += node.riskIntensity;
                nonSkippedCount += 1;

                totalWP += result.weakPointCount;
                totalCrit += result.criticalCount;
                totalLines += result.totalLines;
                totalFiles += result.totalFiles;

                // Classify into risk distribution buckets
                classifyRisk(image.riskDistribution, node.riskIntensity);
            }

            image.nodes.pushBack(node);
        }

        // Build cross-repo edges based on shared risk patterns
        image.edges = buildEdges(image.nodes);

        image.nodeCount = image.nodes.size;
        image.edgeCount = image.edges.size;
        image.totalWeakPoints = totalWP;
        image.totalCritical = totalCrit;
        image.totalLines = totalLines;
        image.totalFiles = totalFiles;

        if nonSkippedCount > 0 {
            image.globalHealth = healthSum / nonSkippedCount: real;
            image.globalRisk = riskSum / nonSkippedCount: real;
        } else {
            image.globalHealth = 1.0;
            image.globalRisk = 0.0;
        }

        return image;
    }

    // ---------------------------------------------------------------------------
    // Edge detection — find relationships between nodes
    // ---------------------------------------------------------------------------

    // Build edges between repos that share risk characteristics.
    // This is the "functional connectivity" layer — repos that have similar
    // vulnerability profiles are likely to share common patterns, dependencies,
    // or architectural decisions that amplify or distribute risk.
    proc buildEdges(nodes: list(ImageNode)): list(ImageEdge) {
        var edges: list(ImageEdge);

        // Risk proximity edges: connect repos with similar risk profiles
        for i in 0..#nodes.size {
            if nodes[i].skipped || nodes[i].error != "" then continue;
            for j in (i+1)..#nodes.size {
                if nodes[j].skipped || nodes[j].error != "" then continue;

                // Connect repos with similar risk intensity (within 0.15)
                const riskDelta = abs(nodes[i].riskIntensity - nodes[j].riskIntensity);
                if riskDelta < 0.15 && nodes[i].riskIntensity > 0.3 {
                    var edge: ImageEdge;
                    edge.fromNode = nodes[i].id;
                    edge.toNode = nodes[j].id;
                    edge.edgeType = "risk_proximity";
                    edge.weight = 1.0 - riskDelta / 0.15;
                    edges.pushBack(edge);
                }

                // Connect repos that share dominant vulnerability categories
                if sharesDominantCategory(nodes[i], nodes[j]) {
                    var edge: ImageEdge;
                    edge.fromNode = nodes[i].id;
                    edge.toNode = nodes[j].id;
                    edge.edgeType = "shared_pattern";
                    edge.weight = 0.8;
                    edges.pushBack(edge);
                }
            }
        }

        return edges;
    }

    proc sharesDominantCategory(a: ImageNode, b: ImageNode): bool {
        // Two nodes share a dominant category if both have the same highest-count
        // category and both have at least 3 findings in it.
        if a.categoryBreakdown.size == 0 || b.categoryBreakdown.size == 0 then
            return false;

        var aDominant: string;
        var aMax = 0;
        for cat in a.categoryBreakdown {
            if cat.count > aMax {
                aMax = cat.count;
                aDominant = cat.name;
            }
        }

        for cat in b.categoryBreakdown {
            if cat.name == aDominant && cat.count >= 3 && aMax >= 3 then
                return true;
        }

        return false;
    }

    // ---------------------------------------------------------------------------
    // Risk classification
    // ---------------------------------------------------------------------------

    proc ref classifyRisk(ref dist: RiskDistribution, risk: real) {
        if risk < 0.2 then dist.healthy += 1;
        else if risk < 0.4 then dist.low += 1;
        else if risk < 0.6 then dist.moderate += 1;
        else if risk < 0.8 then dist.high += 1;
        else dist.critical += 1;
    }

    // Sigmoid function for squashing risk to [0, 1]
    proc sigmoid(x: real, midpoint: real = 5.0, steepness: real = 0.5): real {
        return 1.0 / (1.0 + exp(-(x - midpoint) * steepness));
    }

    // ---------------------------------------------------------------------------
    // JSON output for SystemImage
    // ---------------------------------------------------------------------------

    proc writeSystemImageJson(writer, image: SystemImage) throws {
        writer.writeln("{");
        writer.writeln("  \"format\": \"", image.format, "\",");
        writer.writeln("  \"generated_at\": \"", image.generatedAt, "\",");
        writer.writeln("  \"scan_surface\": \"", image.scanSurface, "\",");
        writer.writeln("  \"global_health\": ", image.globalHealth, ",");
        writer.writeln("  \"global_risk\": ", image.globalRisk, ",");
        writer.writeln("  \"total_weak_points\": ", image.totalWeakPoints, ",");
        writer.writeln("  \"total_critical\": ", image.totalCritical, ",");
        writer.writeln("  \"total_lines\": ", image.totalLines, ",");
        writer.writeln("  \"total_files\": ", image.totalFiles, ",");
        writer.writeln("  \"repos_scanned\": ", image.reposScanned, ",");
        writer.writeln("  \"locales_used\": ", image.localesUsed, ",");
        writer.writeln("  \"node_count\": ", image.nodeCount, ",");
        writer.writeln("  \"edge_count\": ", image.edgeCount, ",");

        // Risk distribution
        writer.writeln("  \"risk_distribution\": {");
        writer.writeln("    \"healthy\": ", image.riskDistribution.healthy, ",");
        writer.writeln("    \"low\": ", image.riskDistribution.low, ",");
        writer.writeln("    \"moderate\": ", image.riskDistribution.moderate, ",");
        writer.writeln("    \"high\": ", image.riskDistribution.high, ",");
        writer.writeln("    \"critical\": ", image.riskDistribution.critical);
        writer.writeln("  },");

        // Nodes
        writer.writeln("  \"nodes\": [");
        for (node, idx) in zip(image.nodes, 0..) {
            if idx > 0 then writer.writeln(",");
            writeNodeJson(writer, node);
        }
        writer.writeln("\n  ],");

        // Edges
        writer.writeln("  \"edges\": [");
        for (edge, idx) in zip(image.edges, 0..) {
            if idx > 0 then writer.writeln(",");
            writeEdgeJson(writer, edge);
        }
        writer.writeln("\n  ]");

        writer.writeln("}");
    }

    proc writeNodeJson(writer, node: ImageNode) throws {
        writer.write("    {");
        writer.write("\"id\": \"", node.id, "\", ");
        writer.write("\"name\": \"", node.name, "\", ");
        writer.write("\"level\": \"", node.level, "\", ");
        writer.write("\"health_score\": ", node.healthScore, ", ");
        writer.write("\"risk_intensity\": ", node.riskIntensity, ", ");
        writer.write("\"weak_point_density\": ", node.weakPointDensity, ", ");
        writer.write("\"weak_point_count\": ", node.weakPointCount, ", ");
        writer.write("\"critical_count\": ", node.criticalCount, ", ");
        writer.write("\"total_files\": ", node.totalFiles, ", ");
        writer.write("\"total_lines\": ", node.totalLines, ", ");
        writer.write("\"fingerprint\": \"", node.fingerprint, "\", ");
        writer.write("\"skipped\": ", if node.skipped then "true" else "false");
        writer.write("}");
    }

    proc writeEdgeJson(writer, edge: ImageEdge) throws {
        writer.write("    {");
        writer.write("\"from\": \"", edge.fromNode, "\", ");
        writer.write("\"to\": \"", edge.toNode, "\", ");
        writer.write("\"type\": \"", edge.edgeType, "\", ");
        writer.write("\"weight\": ", edge.weight);
        writer.write("}");
    }
}
