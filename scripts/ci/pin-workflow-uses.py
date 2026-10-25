#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
"""Pin every `uses:` ref in .github/workflows to a full commit SHA, and
regenerate .github/workflows/actions.lock in the format `gh actions-lock`
emits.

Why this exists as a checked-in script rather than a one-off edit:

  * the estate runs `actions_permissions.sha_pinning_required = true`
    (standards config/settings/repo.json). Under that posture a tag-pinned
    `uses:` is refused at workflow STARTUP: zero jobs, no log, an opaque
    "workflow file issue". That is the same class of outage as an empty
    allowlist, and it is invisible in a green-looking PR.
  * `gh actions-lock` will not touch a workflow whose refs it did not write
    itself, and it rewrites local composite refs into invalid `$/` syntax in
    some modes. Pinning is therefore done here, deterministically, and the
    lockfile is derived from the workflows rather than trusted.

Usage:
    scripts/ci/pin-workflow-uses.py --map pins.json [--check]

`pins.json` maps `owner/repo@ref` -> {"sha": ..., "tag": ...}. It is produced
by scripts/ci/resolve-action-shas.sh so that this script needs no network.

--check exits 1 if any `uses:` is not a 40-hex SHA or if the lockfile would
change; CI runs that mode so drift cannot land.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")
LOCKFILE = WORKFLOW_DIR / "actions.lock"

# `- uses: owner/repo@ref  # comment` / `uses: owner/repo/path@ref`
USES_RE = re.compile(
    r"^(?P<lead>\s*(?:-\s+)?)uses:\s*(?P<ref>[^\s#]+)(?P<trail>\s*#\s*(?P<comment>.*))?$"
)
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SHA_COMMENT_RE = re.compile(r"^\s*[#]?\s*(v?\d[\w.\-+]*)\s*$")


def normalise(ref: str) -> tuple[str, str, str]:
    """Split `owner/repo[/sub/path...]@ref` into (owner/repo, path, ref)."""
    path, _, gitref = ref.partition("@")
    parts = path.split("/")
    slug = "/".join(parts[:2])
    return slug, path, gitref


def workflow_files() -> list[Path]:
    files = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    return [f for f in files if f.is_file()]


def rewrite(workflow: Path, pins: dict[str, dict[str, str]], check: bool) -> tuple[str, bool]:
    text = workflow.read_text(encoding="utf-8")
    changed = False
    out_lines: list[str] = []

    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("#") or "uses:" not in line:
            out_lines.append(line)
            continue
        m = USES_RE.match(line.rstrip("\n"))
        if not m:
            out_lines.append(line)
            continue
        ref = m.group("ref")
        if ref.startswith("./") or ref.startswith("docker://") or "/" not in ref:
            out_lines.append(line)
            continue

        slug, _, gitref = normalise(ref)
        comment = (m.group("comment") or "").strip()

        if SHA_RE.match(gitref):
            # Already pinned. Ensure a version comment names the tag we know.
            tag = None
            for key, info in pins.items():
                if normalise(key)[0].lower() == slug.lower() and info.get("sha", "").lower() == gitref.lower():
                    tag = info.get("tag")
                    break
            if tag and (not comment or SHA_RE.match(comment)):
                new_line = f"{m.group('lead')}uses: {ref}  # {tag}\n"
                if new_line != line:
                    changed = True
                out_lines.append(new_line)
                continue
            out_lines.append(line)
            continue

        key = f"{slug}@{gitref}"
        info = pins.get(key) or next(
            (v for k, v in pins.items() if k.lower() == key.lower()), None
        )
        if not info or not SHA_RE.match(info.get("sha", "")):
            print(f"::error file={workflow}::no SHA known for {key}", file=sys.stderr)
            out_lines.append(line)
            continue

        pin = info["sha"].lower()
        tag = info.get("tag") or gitref
        tail = f"  # {tag}"
        head = f"{m.group('lead')}uses: {ref.replace('@' + gitref, '@' + pin, 1)}"
        new_line = head + tail + "\n"
        if new_line != line:
            changed = True
        out_lines.append(new_line)

    return "".join(out_lines), changed


def refs_in(workflow: Path) -> list[str]:
    refs = []
    for line in workflow.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or "uses:" not in line:
            continue
        m = USES_RE.match(line)
        if not m:
            continue
        ref = m.group("ref")
        if ref.startswith("./") or ref.startswith("docker://") or "/" not in ref:
            continue
        refs.append(ref)
    return sorted(set(refs))


def build_lock(pins: dict[str, dict[str, str]], existing: str) -> str:
    """Emit actions.lock: `workflows:` lists refs as written; `dependencies:`
    is keyed by normalised owner/repo@sha and must carry the *tag* as `ref`
    (never its own SHA — standards#1271)."""
    # Seed tag/identity knowledge from the lockfile that is already committed.
    # We never invent an owner_id/repo_id: if a ref is genuinely new, the
    # maintainer must resolve it (scripts/ci/resolve-action-shas.sh does the
    # network call) and this script refuses to guess.
    ids: dict[str, list[str]] = {}
    by_sha: dict[tuple[str, str], str] = {}

    def slot(key: str) -> list[str]:
        return ids.setdefault(key.lower(), ["", "", ""])

    # Parse the lockfile as entry blocks so a tag-keyed entry can lend its
    # owner/repo ids to the SHA-keyed entry we are about to write.
    id_by_tag: dict[tuple[str, str], tuple[str, str]] = {}
    blocks: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    for line in existing.splitlines():
        m = re.match(r"^    '([^']+)':$", line)
        if m:
            cur = {"key": m.group(1)}
            blocks.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^        (ref|owner_id|repo_id): '?([^'\n]*)'?$", line)
        if m:
            cur[m.group(1)] = m.group(2)
    for b in blocks:
        key = b.get("key", "")
        slug, _, ref = normalise(key)
        if not key:
            continue
        slot(key)[:2] = [b.get("owner_id", ""), b.get("repo_id", "")]
        slot(key)[2] = b.get("ref", "")
        if b.get("owner_id"):
            id_by_tag[(slug.lower(), b.get("ref", ""))] = (
                b["owner_id"],
                b.get("repo_id", ""),
            )
        if SHA_RE.match(ref) and b.get("ref") and not SHA_RE.match(b["ref"]):
            by_sha[(slug.lower(), ref.lower())] = b["ref"]

    # Tags named by the pins map (owner/repo@tag -> sha) beat nothing else.
    for key, info in pins.items():
        slug, _, tag = normalise(key)
        sha = info.get("sha", "")
        if SHA_RE.match(sha) and tag and not SHA_RE.match(tag):
            by_sha[(slug.lower(), sha.lower())] = tag

    # A `# vX.Y.Z` comment on a pinned ref is the reviewer-facing tag.
    comment_tag: dict[tuple[str, str], str] = {}
    for wf in workflow_files():
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = USES_RE.match(line)
            if not m:
                continue
            slug, path, gitref = normalise(m.group("ref"))
            comment = (m.group("comment") or "").strip()
            if not SHA_RE.match(gitref) or not comment or ".github/workflows/" in path:
                continue
            if re.match(r"^v?\d[\w.\-+]*$", comment):
                comment_tag[(slug.lower(), gitref.lower())] = comment

    per_file: dict[str, list[str]] = {}
    deps: dict[str, tuple[str, str, str, str]] = {}
    missing: list[str] = []
    for wf in workflow_files():
        entries = []
        for ref in refs_in(wf):
            slug, path, gitref = normalise(ref)
            entries.append(f"{slug.lower()}@{gitref}")
            # The lockfile models ACTIONS. A reusable workflow
            # (owner/repo/.github/workflows/x.yml@sha) is not keyed.
            if ".github/workflows/" in path or not SHA_RE.match(gitref):
                continue
            key = f"{slug.lower()}@{gitref.lower()}"
            tag = (
                comment_tag.get((slug.lower(), gitref.lower()))
                or by_sha.get((slug.lower(), gitref.lower()))
                or pins.get(f"{slug}@{gitref}", {}).get("tag", "")
            )
            owner_id, repo_id = slot(key)[:2]
            if not (owner_id and repo_id):
                owner_id, repo_id = id_by_tag.get((slug.lower(), tag or ""), ("", ""))
            if not (tag and not SHA_RE.match(tag) and owner_id and repo_id):
                missing.append(f"{slug}@{gitref}")
                continue
            deps[key] = (tag, owner_id, repo_id, gitref.lower())
        per_file[f".github/workflows/{wf.name}"] = sorted(set(entries))

    if missing:
        raise SystemExit(
            "pin-workflow-uses: cannot key these refs in actions.lock "
            "(need a tag and owner/repo ids; see scripts/ci/resolve-action-shas.sh):\n  "
            + "\n  ".join(sorted(set(missing)))
        )

    out = [
        "# This file is machine-generated by `gh actions-lock`.",
        "# Do not edit by hand; run `gh actions-lock` to update.",
        "# Docs: https://gh.io/actions-lockfile",
        "version: 'v0.0.3'",
        "workflows:",
    ]
    for path in sorted(per_file):
        if not per_file[path]:
            out.append(f"    '{path}': []")
            continue
        out.append(f"    '{path}':")
        for e in per_file[path]:
            out.append(f"        - '{e}'")
    out.append("dependencies:")
    for key in sorted(deps):
        tag, owner_id, repo_id, sha = deps[key]
        out.append(f"    '{key}':")
        out.append(f"        ref: '{tag}'")
        out.append(f"        commit: 'sha1-{sha}'")
        out.append(f"        owner_id: {owner_id}")
        out.append(f"        repo_id: {repo_id}")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=True, help="pins JSON (see module docstring)")
    ap.add_argument("--check", action="store_true", help="verify only; never write")
    args = ap.parse_args()

    pins = json.loads(Path(args.map).read_text(encoding="utf-8"))
    failures = 0

    for wf in workflow_files():
        new, changed = rewrite(wf, pins, args.check)
        if changed:
            failures += 1
            if args.check:
                print(f"::error file={wf}::unpinned or un-commented `uses:` (run scripts/ci/pin-workflow-uses.py)", file=sys.stderr)
            else:
                wf.write_text(new, encoding="utf-8")
                print(f"pinned {wf}")

    existing = LOCKFILE.read_text(encoding="utf-8") if LOCKFILE.exists() else ""
    lock = build_lock(pins, existing)
    if lock != existing:
        failures += 1
        if args.check:
            print("::error file=.github/workflows/actions.lock::lockfile is stale (regenerate)", file=sys.stderr)
        else:
            LOCKFILE.write_text(lock, encoding="utf-8")
            print("regenerated actions.lock")

    if args.check and failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
