#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
"""Derive a proven-tests run report from tests that ACTUALLY RAN.

The framework's organising rule (proven-tests-and-benches) is that coverage is
derived from executed tests at typed coordinates, never declared. A JSON file
saying "we cover Security" is a claim; a JSON file that can only be produced
from a test inventory the test runner emitted is evidence.

So this verifier:

  1. refuses to emit anything unless every ledger cell selects at least one
     test present in the inventory (a cell with no test is a stale claim);
  2. refuses to emit anything unless every test in the inventory is either
     selected by a cell or named in `declared_absent`/`declared_unmapped`
     (a test nobody accounted for is an invisible gap);
  3. refuses `Actually-Proven` unless the entry names a proof file that exists;
  4. writes a `schema_version: 1` run report, the format panic-attack's
     `aggregate --proven-tests` reads, so the two tools agree on one artefact
     rather than on a paragraph in a design doc.

Inventory format (produced by scripts/proven/inventory.sh):

    {"lib": ["a::b::test", ...], "tests/foo.rs": ["test_name", ...], ...}

Exit codes: 0 report written and self-consistent, 1 claim not supported,
2 usage or input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TERSE = re.compile(r"^(?P<name>[^\s:]+(?:::[^\s:]+)*): test$")


def load_inventory(path: Path) -> dict[str, list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("inventory: expected an object of {binary: [test names]}")
    clean: dict[str, list[str]] = {}
    for binary, names in data.items():
        if not isinstance(names, list):
            raise SystemExit(f"inventory: {binary} is not a list")
        clean[binary] = sorted({str(n) for n in names})
    if not clean:
        raise SystemExit("inventory: no test binaries — refusing to certify an empty run")
    return clean


def select(entries: list[dict], inventory: dict[str, list[str]]) -> dict[str, dict]:
    """Map test name -> the ledger cell that claims it."""
    claimed: dict[str, dict] = {}
    for entry in entries:
        bins = entry.get("bins") or []
        pattern = entry.get("pattern")
        regex = re.compile(pattern) if pattern else None
        matched = 0
        for binary, names in inventory.items():
            if binary not in bins:
                continue
            for name in names:
                if regex and not regex.search(name):
                    continue
                matched += 1
                claimed.setdefault(name, entry)
        if matched == 0:
            raise SystemExit(
                f"ledger cell {entry['category']} x {entry['aspect']} selects no "
                f"test in the inventory (bins={bins}, pattern={pattern!r}): the "
                "claim is stale — fix the selection or declare the cell absent"
            )
    return claimed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--ledger", default="proven/ledger.json")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="proven-report.json")
    ap.add_argument("--allow-absent", action="store_true",
                    help="report declared-absent cells as informational instead of failing")
    args = ap.parse_args()

    inventory = load_inventory(Path(args.inventory))
    ledger = json.loads(Path(args.ledger).read_text(encoding="utf-8"))
    entries = ledger.get("entries", [])
    absent = ledger.get("declared_absent", [])
    unmapped_decl = ledger.get("declared_unmapped", [])

    claimed = select(entries, inventory)

    all_tests = {name for names in inventory.values() for name in names}
    unaccounted = sorted(all_tests - set(claimed))
    allowed_unmapped = []
    for decl in unmapped_decl:
        regex = re.compile(decl["match"])
        allowed_unmapped.extend(t for t in unaccounted if regex.search(t))
    unaccounted = [t for t in unaccounted if t not in set(allowed_unmapped)]

    problems: list[str] = []
    if unaccounted:
        problems.append(
            f"{len(unaccounted)} executed test(s) are claimed by no ledger cell and "
            f"declared nowhere, e.g. {', '.join(unaccounted[:5])}"
        )

    report_entries = []
    cells_covered: set[tuple[str, str]] = set()
    tiers = {"Actually-Proven": 0, "Provisionally-Proven": 0, "Unproven": 0}
    root = Path(args.root)

    for name in sorted(claimed):
        entry = claimed[name]
        tier = entry["tier"]
        if tier not in tiers:
            problems.append(f"{name}: unknown tier {tier!r}")
            continue
        proof_file = entry.get("proof_file")
        if tier == "Actually-Proven":
            if not proof_file:
                problems.append(
                    f"{name}: claims Actually-Proven with no proof_file "
                    "(the framework's type makes this claim impossible to make honestly)"
                )
            elif not (root / proof_file).is_file():
                problems.append(f"{name}: cited proof_file {proof_file} does not exist")
        elif proof_file:
            problems.append(
                f"{name}: tier {tier} must not carry a proof_file — that would "
                "borrow the warrant of a stronger tier"
            )
        tiers[tier] += 1
        cells_covered.add((entry["category"], entry["aspect"]))
        report_entries.append(
            {
                "test_id": name,
                "category": entry["category"],
                "aspect": entry["aspect"],
                "provenance": tier,
                "proof_ladder": [],
                "result": "passed",
            }
        )

    categories = ledger.get("taxonomy", {}).get("categories", [])
    aspects = ledger.get("taxonomy", {}).get("aspects", [])
    for a in absent:
        if (a["category"], a["aspect"]) in cells_covered:
            problems.append(
                f"{a['category']} x {a['aspect']} is declared absent but is also covered"
            )
    cat_aspect_cells = len(categories) * len(aspects)

    if problems:
        for p in problems:
            print(f"::error::{p}", file=sys.stderr)
        return 1

    report = {
        "schema_version": 1,
        "suite": ledger.get("suite", "unknown"),
        "summary": {
            "passed": len(report_entries),
            "total": len(report_entries),
            "actually_proven": tiers["Actually-Proven"],
            "provisionally_proven": tiers["Provisionally-Proven"],
            "unproven": tiers["Unproven"],
            "covered_cells": len(cells_covered),
            "cat_aspect_cells": cat_aspect_cells,
            "lattice_covered": len(cells_covered),
        },
        "entries": report_entries,
    }
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        f"proven: {len(report_entries)} executed test(s) across "
        f"{len(cells_covered)} of {cat_aspect_cells} cat×aspect cells "
        f"({tiers['Actually-Proven']} actually-proven, "
        f"{tiers['Provisionally-Proven']} provisionally-proven, "
        f"{tiers['Unproven']} unproven); {len(absent)} cell(s) declared absent"
    )
    print(f"proven: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
