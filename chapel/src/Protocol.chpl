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
    use Path;

    // Safe wrappers around throwing FileSystem procs
    proc safeIsFile(path: string): bool {
        try { return isFile(path); } catch { return false; }
    }
    proc safeIsDir(path: string): bool {
        try { return isDir(path); } catch { return false; }
    }

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
                return try! fingerprints[repoPath];
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
        // Scan past the key, then collect digits — avoids byteIndex arithmetic
        var afterKey: string;
        try { afterKey = json[idx..]; } catch { return 0; }
        var skipped = 0;
        var numStr: string;
        for ch in afterKey {
            skipped += 1;
            if skipped <= key.size then continue;
            if ch >= "0" && ch <= "9" then
                numStr += ch;
            else if numStr.size > 0 then
                break;
        }
        if numStr.size > 0 {
            try { return numStr: int; } catch { return 0; }
        }
        return 0;
    }

    proc countSeverity(json: string, severity: string): int {
        // Slice-and-search: advance through the string by taking suffixes.
        const searchStr = "\"severity\":\"" + severity + "\"";
        var count = 0;
        var remaining = json;
        while remaining.size > 0 {
            const idx = remaining.find(searchStr);
            if idx == -1 then break;
            count += 1;
            remaining = try! (try! remaining[idx..])[searchStr.size..];
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
    // Processes line by line; each entry line is: "key": "value",
    // Extracts using extractQuotedString with marker built from the known
    // prefix "fingerprints" key — avoids byteIndex arithmetic entirely.
    proc loadFingerprintCacheFromFile(path: string): FingerprintCache {
        var cache: FingerprintCache;
        if path == "" || !safeIsFile(path) then return cache;

        try {
            var f = open(path, ioMode.r);
            var reader = f.reader(locking=false);
            var inFingerprints = false;
            var line: string;
            while reader.readLine(line, stripNewline=true) {
                const trimmed = line.strip();
                if trimmed.startsWith("\"fingerprints\"") then {
                    inFingerprints = true;
                    continue;
                }
                if inFingerprints && trimmed == "}" then break;
                if !inFingerprints then continue;
                // Each entry is: "repo/path": "blake3hash",
                // Scan for first "..." then ": " then second "..."
                var inKey = false;
                var inVal = false;
                var sawColon = false;
                var k2: string;
                var v2: string;
                for ch in trimmed {
                    if ch == "\"" && !inKey && !sawColon && k2 == "" {
                        inKey = true;
                    } else if ch == "\"" && inKey && !sawColon {
                        inKey = false;
                    } else if inKey {
                        k2 += ch;
                    } else if ch == ":" && k2 != "" && !sawColon {
                        sawColon = true;
                    } else if ch == "\"" && sawColon && !inVal {
                        inVal = true;
                    } else if ch == "\"" && inVal {
                        inVal = false;
                        break;
                    } else if inVal {
                        v2 += ch;
                    }
                }
                if k2 != "" && v2 != "" then
                    cache.fingerprints[k2] = v2;
            }
        } catch {
            // Cache is optional — if parsing fails, return empty cache
        }

        return cache;
    }

    // Default entry point: returns empty cache (caller should use
    // loadFingerprintCacheFromFile with the configured path instead).
    proc loadFingerprintCache(): FingerprintCache {
        return loadFingerprintCacheFromFile("");
    }

    // Extract a quoted string value following a JSON key, e.g. "key":"value".
    // Uses character iteration to avoid byteIndex arithmetic entirely.
    proc extractQuotedString(json: string, key: string): string {
        const idx = json.find(key);
        if idx == -1 then return "";
        // Get the substring starting at the key match
        var afterKey: string;
        try { afterKey = json[idx..]; } catch { return ""; }
        // Scan character by character: find the quoted value after the key
        var inValue = false;
        var result: string;
        // Skip key.size characters first (the key itself), then find "..."
        var skipped = 0;
        for ch in afterKey {
            skipped += 1;
            if skipped <= key.size then continue;
            // Now past the key — look for the opening quote of the value
            if ch == "\"" && !inValue {
                inValue = true;
                continue;
            }
            if ch == "\"" && inValue {
                break; // closing quote
            }
            if inValue then result += ch;
        }
        return result;
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

}
