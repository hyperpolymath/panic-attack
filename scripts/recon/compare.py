#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
"""Compare two independent scans of this repository against a frozen baseline.

The baseline is a *debt ledger*, not a target. It exists so that:

  * a category that did not exist yesterday fails the job today (a regression),
  * a count that rises above what was accepted fails (new debt),
  * a count that FALLS is reported, so paying debt down is visible and the
    baseline can be tightened in the same PR that fixed it.

Findings that are simply standing debt never fail the job. Failing on them
would create pressure to suppress them — the failure mode this estate keeps
paying for (see panic-attack's own user-classification registry doctrine).

Both scanner outputs are read defensively on purpose. `pons` is v0.1 and its
JSON envelope is still settling, so findings are located structurally rather
than by a hard-coded path: any list named `findings` at any depth, or the
`weak_points` array panic-attack emits. If a shape is not recognised the run
says so and does not silently count zero.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def walk_lists(node, wanted: set[str], path=""):
    """Yield (json path, list) for every list whose key is in `wanted`."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            if key in wanted and isinstance(value, list):
                yield here, value
            yield from walk_lists(value, wanted, here)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk_lists(value, wanted, f"{path}[{i}]")


def label(finding: dict) -> str:
    for key in ("category", "rule_id", "rule", "id", "code", "check"):
        value = finding.get(key)
        if isinstance(value, str):
            return value
    return "unknown"


def counts_from(path: Path, wanted: set[str], name: str) -> tuple[Counter, list[str]]:
    notes: list[str] = []
    if not path.exists() or path.stat().st_size == 0:
        notes.append(f"{name}: no report at {path} — counted as absent, not as zero")
        return Counter(), notes
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        notes.append(f"{name}: report is not JSON ({exc})")
        return Counter(), notes

    counter: Counter = Counter()
    found = False
    for where, findings in walk_lists(data, wanted):
        found = True
        for finding in findings:
            if isinstance(finding, dict):
                counter[label(finding)] += 1
        notes.append(f"{name}: {len(findings)} finding(s) at {where}")
    if not found:
        notes.append(
            f"{name}: no {'/'.join(sorted(wanted))} array in the report — shape not "
            "recognised; counted as absent rather than as clean"
        )
    return counter, notes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default="recon/baseline.json")
    ap.add_argument("--assail", required=True)
    ap.add_argument("--pons", required=True)
    ap.add_argument("--summary")
    ap.add_argument("--no-fail", action="store_true")
    args = ap.parse_args()

    baseline = (
        json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        if Path(args.baseline).exists()
        else {}
    )
    scanners = {
        "assail": (Path(args.assail), {"weak_points"}),
        "pons": (Path(args.pons), {"findings", "results"}),
    }

    lines: list[str] = ["## Recon: two independent scans", ""]
    regressions = 0
    observed: dict[str, dict[str, int]] = {}

    for name, (path, wanted) in scanners.items():
        counter, notes = counts_from(path, wanted, name)
        observed[name] = dict(sorted(counter.items()))
        frozen = baseline.get(name) or {}
        lines.append(f"### {name}")
        lines.append("")
        for note in notes:
            lines.append(f"- {note}")
        if counter:
            lines.append("")
            lines.append("| category | observed | baseline | verdict |")
            lines.append("|---|---|---|---|")
            for category, count in sorted(counter.items()):
                allowed = frozen.get(category)
                if allowed is None:
                    verdict = "**NEW (fails)**" if frozen else "new (baseline empty)"
                    if frozen:
                        regressions += 1
                elif count > allowed:
                    verdict = f"**+{count - allowed} (fails)**"
                    regressions += 1
                elif count < allowed:
                    verdict = f"−{allowed - count} (debt paid; tighten the baseline)"
                else:
                    verdict = "at baseline"
                lines.append(f"| {category} | {count} | {allowed if allowed is not None else '—'} | {verdict} |")
        else:
            lines.append("- no findings counted")
        missing = sorted(set(frozen) - set(counter))
        if missing:
            lines.append("")
            lines.append(f"- baseline categories no longer reported: {', '.join(missing)}")
        lines.append("")

    lines.append("### Freeze or tighten the baseline")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(observed, indent=2, sort_keys=True))
    lines.append("```")

    out = "\n".join(lines)
    print(out)
    if args.summary:
        Path(args.summary).write_text(
            (Path(args.summary).read_text(encoding="utf-8") if Path(args.summary).exists() else "")
            + out
            + "\n",
            encoding="utf-8",
        )

    if args.no_fail:
        print("recon: --no-fail, reporting only", file=sys.stderr)
        return 0
    if regressions:
        print(
            f"::error::{regressions} category regression(s) against {args.baseline}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
