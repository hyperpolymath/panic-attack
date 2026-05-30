// SPDX-License-Identifier: MPL-2.0

//
// two_repo_smoke — Chapel-side data-flow smoke test.
//
// Purpose: catch regressions in the RepoResult → SystemImage → JSON
// pipeline (Protocol.chpl + Imaging.chpl) WITHOUT requiring the
// panic-attack Rust binary or a real git workdir. Runs in single-locale
// mode in <5s on stock CI hardware.
//
// Scope:
//   * Builds two synthetic RepoResult records (no scanning, no FFI).
//   * Drives buildSystemImage() to compute aggregates + edges.
//   * Writes the SystemImage JSON to a temp file via writeSystemImageJson().
//   * Asserts the four ImageNode fields that previously silently dropped
//     out of writeNodeJson() (path, high_count, error, category_breakdown)
//     are present and well-formed.
//
// Companion gates (in .github/workflows/chapel-ci.yml):
//   * chapel-multilocale: end-to-end -nl 2 test against the real binary.
//   * chapel-cli-contract: Rust↔Chapel argv-vs-describe-contract diff.
//   * chapel-rust-diff: rayon vs Chapel single-locale aggregate parity.
//

use FileSystem;
use IO;
use List;
use Protocol;
use Imaging;

config const outputPath = "/tmp/two-repo-smoke.json";
config const verbose = false;

proc makeCategories(): list(CategoryCount) {
    var cats: list(CategoryCount);
    var c1: CategoryCount;
    c1.name = "UnsafeCode"; c1.count = 3; c1.severity = "high";
    var c2: CategoryCount;
    c2.name = "PanicPath"; c2.count = 2; c2.severity = "medium";
    cats.pushBack(c1);
    cats.pushBack(c2);
    return cats;
}

proc makeRepoResult(name: string, path: string, wp: int, crit: int, hi: int,
                     lines: int, fpr: string, err: string = ""): RepoResult {
    var r: RepoResult;
    r.repoName = name;
    r.repoPath = path;
    r.weakPointCount = wp;
    r.criticalCount = crit;
    r.highCount = hi;
    r.totalFiles = 5;
    r.totalLines = lines;
    r.fingerprint = fpr;
    r.error = err;
    r.skipped = false;
    r.categories = makeCategories();
    return r;
}

proc assertContains(haystack: string, needle: string, tag: string): bool {
    if haystack.find(needle) == -1 {
        writeln("smoke: FAIL [", tag, "] — '", needle, "' not found in output");
        return false;
    }
    if verbose then writeln("smoke: ok [", tag, "]");
    return true;
}

proc main(): int {
    var results: [0..#2] RepoResult;
    results[0] = makeRepoResult("repo-alpha", "/tmp/smoke/repo-alpha",
                                 5, 1, 2, 1000, "f0a1b2c3");
    // The second repo includes an embedded quote in its error to exercise
    // the new jsonEscape path that the silent-loss fix introduced.
    results[1] = makeRepoResult("repo-beta", "/tmp/smoke/repo-beta",
                                 8, 2, 3, 2000, "deadbeef",
                                 "parse error at \"line 3\"");

    var image = buildSystemImage(results, 2);
    image.scanSurface = "two-repo-smoke";
    image.generatedAt = "2026-05-30T00:00:00Z";

    {
        var f = open(outputPath, ioMode.cw);
        var w = f.writer();
        writeSystemImageJson(w, image);
        w.close();
        f.close();
    }

    // Read it back and assert the new fields land in the JSON.
    var blob: string;
    {
        var f = open(outputPath, ioMode.r);
        var r = f.reader();
        var line: string;
        while r.readLine(line) do blob += line;
        r.close();
        f.close();
    }

    var ok = true;
    ok &&= assertContains(blob, "\"repos_scanned\": 2", "repos_scanned");
    ok &&= assertContains(blob, "\"path\": \"/tmp/smoke/repo-alpha\"", "ImageNode.path emitted");
    ok &&= assertContains(blob, "\"high_count\": 2", "ImageNode.highCount emitted");
    ok &&= assertContains(blob, "\"high_count\": 3", "ImageNode.highCount emitted (repo-beta)");
    ok &&= assertContains(blob, "\"category_breakdown\":", "ImageNode.categoryBreakdown emitted");
    ok &&= assertContains(blob, "\"name\": \"UnsafeCode\"", "category UnsafeCode preserved");
    ok &&= assertContains(blob, "\"severity\": \"high\"", "category severity preserved");
    ok &&= assertContains(blob, "parse error at \\\"line 3\\\"", "ImageNode.error emitted with JSON-escaped quotes");
    // buildSystemImage excludes errored repos from aggregates, so totalWP/totalCrit
    // count repo-alpha only. Per-node counts (high_count etc.) are still serialised
    // for both — that's what the four-field silent-loss fix guarantees.
    ok &&= assertContains(blob, "\"total_weak_points\": 5", "aggregate total_weak_points (alpha only; beta errored)");
    ok &&= assertContains(blob, "\"total_critical\": 1", "aggregate total_critical (alpha only)");

    try { remove(outputPath); } catch { }

    if ok {
        writeln("smoke: PASS (two-repo SystemImage round-trip + 4 silent-loss fields)");
        return 0;
    } else {
        writeln("smoke: FAIL — see assertions above");
        return 1;
    }
}
