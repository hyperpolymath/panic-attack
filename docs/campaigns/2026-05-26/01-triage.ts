#!/usr/bin/env -S deno run --allow-read --allow-write
// panic-attack estate sweep — triage
// Reads per-repo AssailReport JSONs, classifies findings, emits a PR-candidate plan.

import { walk } from "https://deno.land/std@0.224.0/fs/walk.ts";
import { dirname, basename, resolve } from "https://deno.land/std@0.224.0/path/mod.ts";

type Severity = "Low" | "Medium" | "High" | "Critical";
type WeakPoint = {
  category: string;       // PA001..PA025 or enum name
  location?: string;
  file?: string;
  line?: number;
  severity: Severity;
  description: string;
  suppressed: boolean;
};
type AssailReport = {
  schema_version: string;
  program_path: string;
  language: string;
  weak_points: WeakPoint[];
  suppressed_count?: number;
};

const PROOF_EXTS = new Set([
  ".lean", ".agda", ".lagda", ".v", ".idr", ".idr2", ".fst", ".fsti",
  ".thy", ".spthy", ".smt2", ".tla",
]);

const PARKED_PROOF_DEBTS = [
  { repo: "ephapax", path: "formal/Semantics.v", line: 3327, reason: "preservation, deferred per ephapax-preservation-closure-plan" },
  { repo: "betlang", file_match: "substTop_preserves_typing", reason: "discharge recipe in PR#27 body" },
];

// PA-categories with reliable automated fixes (Critical/High only)
const AUTOFIX_OK = new Set([
  "PA001", "UnsafeCode",          // unwrap → ?, mostly
  "PA006", "PanicPath",
  "PA022", "CryptoMisuse",        // md5/sha1 → sha256 (limited)
]);

// PA-categories that need human judgement → file as issue
const ISSUE_ONLY = new Set([
  "PA023", "SupplyChain",         // version pinning choices
  "PA024", "InputBoundary",       // schema validation design
  "PA025", "MutationGap",         // requires new test infra
  "PA021", "ProofDrift",          // proof refactor, never blind-fix
]);

type Bucket = "autofix" | "issue" | "proof-draft" | "skip-known" | "skip-suppressed" | "skip-unknown-cat";

type PrCandidate = {
  repo: string;
  bucket: Bucket;
  category: string;
  severity: Severity;
  file: string;
  line?: number;
  description: string;
};

function categoryCode(cat: string): string {
  // category may be either "PA001" or "UnsafeCode" or "{ category: "UnsafeCode" }"
  if (/^PA\d{3}/.test(cat)) return cat;
  const map: Record<string, string> = {
    UnsafeCode: "PA001", PanicPath: "PA006",
    CommandInjection: "PA003", UnsafeDeserialization: "PA004",
    AtomExhaustion: "PA005", UnsafeFFI: "PA007",
    PathTraversal: "PA008", HardcodedSecret: "PA009",
    ProofDrift: "PA021", CryptoMisuse: "PA022",
    SupplyChain: "PA023", InputBoundary: "PA024",
    MutationGap: "PA025",
  };
  return map[cat] ?? cat;
}

function isProofFile(file: string): boolean {
  const dot = file.lastIndexOf(".");
  if (dot < 0) return false;
  return PROOF_EXTS.has(file.slice(dot).toLowerCase());
}

function isParked(repo: string, wp: WeakPoint): boolean {
  for (const p of PARKED_PROOF_DEBTS) {
    if ((p as any).repo === repo) {
      if ((p as any).path && wp.file?.endsWith((p as any).path) && wp.line === (p as any).line) return true;
      if ((p as any).file_match && wp.description.includes((p as any).file_match)) return true;
    }
  }
  return false;
}

function classify(repo: string, wp: WeakPoint): Bucket {
  if (wp.suppressed) return "skip-suppressed";
  if (wp.severity !== "Critical" && wp.severity !== "High") return "skip-unknown-cat"; // out-of-scope this wave
  if (isParked(repo, wp)) return "skip-known";
  // Skip in-tree worktree-branch findings — main checkout state is the source of truth
  if (wp.file && (wp.file.includes(".claude/worktrees/") || wp.file.includes("/_wt-"))) return "skip-known";
  const code = categoryCode(wp.category);
  if (wp.file && isProofFile(wp.file)) return "proof-draft";
  if (ISSUE_ONLY.has(code) || ISSUE_ONLY.has(wp.category)) return "issue";
  if (AUTOFIX_OK.has(code) || AUTOFIX_OK.has(wp.category)) return "autofix";
  return "issue"; // default conservative: needs human eye
}

async function main() {
  const [perRepoDir, planPath] = Deno.args;
  if (!perRepoDir || !planPath) {
    console.error("Usage: 01-triage.ts <per-repo-dir> <plan.json>");
    Deno.exit(2);
  }

  const candidates: PrCandidate[] = [];
  let scanned = 0;

  for await (const entry of walk(perRepoDir, { exts: [".json"], maxDepth: 1 })) {
    scanned++;
    const repo = basename(entry.path).replace(/\.json$/, "");
    let raw: string;
    try { raw = await Deno.readTextFile(entry.path); }
    catch { continue; }
    let rpt: AssailReport;
    try { rpt = JSON.parse(raw); }
    catch { console.error(`bad json: ${entry.path}`); continue; }
    if (!rpt.weak_points) continue;

    for (const wp of rpt.weak_points) {
      const bucket = classify(repo, wp);
      candidates.push({
        repo,
        bucket,
        category: categoryCode(wp.category),
        severity: wp.severity,
        file: wp.file ?? wp.location ?? "<unknown>",
        line: wp.line,
        description: wp.description,
      });
    }
  }

  // Group by (repo, file, category) — that's the PR unit
  const groups = new Map<string, PrCandidate[]>();
  for (const c of candidates) {
    if (c.bucket.startsWith("skip-")) continue;
    const key = `${c.repo}::${c.file.split("/").slice(0, -1).join("/")}::${c.category}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(c);
  }

  const summary = {
    generated_at: new Date().toISOString(),
    per_repo_scanned: scanned,
    total_candidates: candidates.length,
    by_bucket: Object.fromEntries(
      ["autofix", "issue", "proof-draft", "skip-suppressed", "skip-known", "skip-unknown-cat"].map(
        b => [b, candidates.filter(c => c.bucket === b).length]
      )
    ),
    by_repo: Object.fromEntries(
      [...new Set(candidates.map(c => c.repo))].sort().map(r => [
        r,
        candidates.filter(c => c.repo === r && !c.bucket.startsWith("skip-")).length,
      ]).filter(([_, n]) => (n as number) > 0)
    ),
    pr_groups: [...groups.entries()].map(([k, members]) => ({
      key: k,
      repo: members[0].repo,
      file_dir: k.split("::")[1],
      category: members[0].category,
      bucket: members[0].bucket,
      finding_count: members.length,
      severities: [...new Set(members.map(m => m.severity))],
      examples: members.slice(0, 3),
    })),
  };

  await Deno.writeTextFile(planPath, JSON.stringify(summary, null, 2));
  console.error(`triage complete: ${candidates.length} candidates, ${groups.size} PR groups → ${planPath}`);
  console.error(`buckets: ${JSON.stringify(summary.by_bucket)}`);
}

main();
