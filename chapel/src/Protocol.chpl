// SPDX-License-Identifier: PMPL-1.0-or-later

//
// Protocol — JSON contract types between Chapel orchestrator and panic-attack binary.
//
// These records mirror the Rust types in `src/assemblyline.rs` and `src/mass_panic/`.
// The Chapel orchestrator invokes `panic-attack assail --output-format=json` and
// parses the JSON output into these records. Results are aggregated and forwarded
// to the Imaging module for system-wide health imaging.
//

module Protocol {
    use IO;
    use Map;
    use List;
    use FileSystem;

    // ---------------------------------------------------------------------------
    // RepoResult — outcome of scanning a single repository
    // ---------------------------------------------------------------------------

    record RepoResult {
        var repoPath: string;
        var repoName: string;
        var weakPointCount: int = 0;
        var criticalCount: int = 0;
        var highCount: int = 0;
        var totalFiles: int = 0;
        var totalLines: int = 0;
        var crashes: int = 0;
        var verdict: string = "";
        var error: string = "";
        var fingerprint: string = "";
        var skipped: bool = false;

        // Per-category breakdown for imaging heat maps
        var categories: list(CategoryCount);
    }

    record CategoryCount {
        var name: string;
        var count: int;
        var severity: string;
    }

    // ---------------------------------------------------------------------------
    // AssemblylineReport — aggregate report across all repos
    // ---------------------------------------------------------------------------

    record AssemblylineReport {
        var createdAt: string;
        var directory: string;
        var reposScanned: int;
        var reposWithFindings: int;
        var reposSkipped: int;
        var totalWeakPoints: int;
        var totalCritical: int;
    }

    // ---------------------------------------------------------------------------
    // FingerprintCache — BLAKE3 hashes for incremental scanning
    // ---------------------------------------------------------------------------

    record FingerprintCache {
        var fingerprints: map(string, string);

        proc has(repoPath: string): bool {
            return fingerprints.contains(repoPath);
        }

        proc get(repoPath: string): string {
            if fingerprints.contains(repoPath) then
                return fingerprints[repoPath];
            return "";
        }

        proc ref set(repoPath: string, fp: string) {
            fingerprints[repoPath] = fp;
        }
    }

    // ---------------------------------------------------------------------------
    // JSON parsing (minimal hand-rolled parser for panic-attack output)
    // ---------------------------------------------------------------------------

    proc parseRepoResult(jsonStr: string, repoPath: string): RepoResult {
        var result: RepoResult;
        result.repoPath = repoPath;
        result.repoName = basename(repoPath);

        // Extract key fields from JSON using simple string matching.
        // This avoids a full JSON parser dependency — panic-attack's output
        // format is stable and well-defined by the panicbot JSON contract.
        result.weakPointCount = extractInt(jsonStr, "\"weak_points\":");
        result.criticalCount = countSeverity(jsonStr, "Critical");
        result.highCount = countSeverity(jsonStr, "High");
        result.totalFiles = extractInt(jsonStr, "\"total_files\":");
        result.totalLines = extractInt(jsonStr, "\"total_lines\":");

        return result;
    }

    proc extractInt(json: string, key: string): int {
        const idx = json.find(key);
        if idx == -1 then return 0;
        const afterKey = json[idx + key.size..];
        var numStr: string;
        for ch in afterKey {
            if ch >= "0" && ch <= "9" then
                numStr += ch;
            else if numStr.size > 0 then
                break;
        }
        if numStr.size > 0 then return numStr: int;
        return 0;
    }

    proc countSeverity(json: string, severity: string): int {
        var count = 0;
        var searchStr = "\"severity\":\"" + severity + "\"";
        var pos = 0;
        while true {
            const idx = json.find(searchStr, pos);
            if idx == -1 then break;
            count += 1;
            pos = idx + searchStr.size;
        }
        return count;
    }

    // ---------------------------------------------------------------------------
    // JSON writing helpers
    // ---------------------------------------------------------------------------

    proc writeAssemblylineJson(writer, report: AssemblylineReport) throws {
        writer.writeln("{");
        writer.writeln("  \"format\": \"panic-attack.assemblyline.v2\",");
        writer.writeln("  \"created_at\": \"", report.createdAt, "\",");
        writer.writeln("  \"directory\": \"", report.directory, "\",");
        writer.writeln("  \"repos_scanned\": ", report.reposScanned, ",");
        writer.writeln("  \"repos_with_findings\": ", report.reposWithFindings, ",");
        writer.writeln("  \"repos_skipped\": ", report.reposSkipped, ",");
        writer.writeln("  \"total_weak_points\": ", report.totalWeakPoints, ",");
        writer.writeln("  \"total_critical\": ", report.totalCritical);
        writer.writeln("}");
    }

    // Load fingerprint cache from a file path. Parses the JSON format:
    //   {"fingerprints":{"repo/path":"blake3hash",...}}
    // Uses hand-rolled string matching consistent with the rest of Protocol.
    proc loadFingerprintCacheFromFile(path: string): FingerprintCache {
        var cache: FingerprintCache;
        if path == "" || !isFile(path) then return cache;

        try {
            var f = open(path, ioMode.r);
            var reader = f.reader(locking=false);
            var contents: string;
            var line: string;
            while reader.readLine(line, stripNewline=true) {
                contents += line;
            }

            // Find the "fingerprints" object within the JSON
            const fpKey = "\"fingerprints\"";
            const fpIdx = contents.find(fpKey);
            if fpIdx == -1 then return cache;

            // Locate the opening brace of the fingerprints object
            const afterKey = contents[fpIdx + fpKey.size..];
            const braceIdx = afterKey.find("{");
            if braceIdx == -1 then return cache;

            // Extract the inner object content between { and matching }
            const innerStart = braceIdx + 1;
            var depth = 1;
            var innerEnd = innerStart;
            for i in innerStart + 1..afterKey.size - 1 {
                if afterKey[i] == "{" then depth += 1;
                else if afterKey[i] == "}" then depth -= 1;
                if depth == 0 {
                    innerEnd = i;
                    break;
                }
            }

            const inner = afterKey[innerStart..innerEnd - 1];

            // Parse key-value pairs: "path":"hash"
            // Walk through the inner string looking for quoted strings
            var pos = 0;
            while pos < inner.size {
                // Find next key (quoted string)
                const keyStart = inner.find("\"", pos);
                if keyStart == -1 then break;
                const keyEnd = inner.find("\"", keyStart + 1);
                if keyEnd == -1 then break;
                const key = inner[keyStart + 1..keyEnd - 1];

                // Find colon after key
                const colonIdx = inner.find(":", keyEnd + 1);
                if colonIdx == -1 then break;

                // Find value (quoted string after colon)
                const valStart = inner.find("\"", colonIdx + 1);
                if valStart == -1 then break;
                const valEnd = inner.find("\"", valStart + 1);
                if valEnd == -1 then break;
                const val = inner[valStart + 1..valEnd - 1];

                cache.fingerprints[key] = val;
                pos = valEnd + 1;
            }
        } catch e: Error {
            // Cache is optional — if parsing fails, return empty cache
        }

        return cache;
    }

    // Default entry point: returns empty cache (caller should use
    // loadFingerprintCacheFromFile with the configured path instead).
    proc loadFingerprintCache(): FingerprintCache {
        return loadFingerprintCacheFromFile("");
    }

    proc buildReport(results: [] RepoResult, totalRepos: int,
                     directory: string, startTime: real): AssemblylineReport {
        var report: AssemblylineReport;
        report.directory = directory;
        report.reposScanned = totalRepos;
        report.reposSkipped = 0;
        report.reposWithFindings = 0;
        report.totalWeakPoints = 0;
        report.totalCritical = 0;

        for result in results {
            if result.skipped then
                report.reposSkipped += 1;
            if result.weakPointCount > 0 then
                report.reposWithFindings += 1;
            report.totalWeakPoints += result.weakPointCount;
            report.totalCritical += result.criticalCount;
        }

        return report;
    }

    proc basename(path: string): string {
        const idx = path.rfind("/");
        if idx == -1 then return path;
        return path[idx+1..];
    }
}
