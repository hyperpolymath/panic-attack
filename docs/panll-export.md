<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

# PanLL Export (Event-Chain Bridge)

`panic-attack` can export an assault report into a lightweight PanLL-compatible
event-chain model. This gives PanLL a stable input describing stress events,
timing, and outcomes without forcing a heavy schema dependency.

## Command

```bash
panic-attack panll path/to/assault-report.json --output panll-event-chain.json
```

## Format (v0)

```json
{
  "format": "panll.event-chain.v0",
  "generated_at": "2026-02-09T19:12:00Z",
  "source": {
    "tool": "panic-attack",
    "report_path": "reports/assault-report.json"
  },
  "summary": {
    "program": "/path/to/target",
    "weak_points": 7,
    "critical_weak_points": 1,
    "total_crashes": 2,
    "robustness_score": 63.5
  },
  "timeline": {
    "duration_ms": 120000,
    "events": 5
  },
  "event_chain": [
    {
      "id": "cpu-1",
      "axis": "cpu",
      "start_ms": 0,
      "duration_ms": 30000,
      "intensity": "Heavy",
      "status": "ran",
      "peak_memory": null,
      "notes": null
    }
  ],
  "constraints": []
}
```

Notes:
- If the report includes ambush timeline metadata, the `event_chain` is derived
  from timeline events.
- Otherwise, each attack result becomes a single event entry with `start_ms`
  unset and `intensity = "unknown"`.

## Next Steps

Future versions can enrich this export with constraints, event dependencies,
and a full PanLL graph import/export pipeline.

## Groove discovery

panic-attack also advertises its export capability through the Gossamer groove
protocol so PanLL and other groove-aware systems can discover it automatically.
Run `panic-attack groove --port 7600` and curl
`http://localhost:7600/.well-known/groove` to verify the manifest. The minimal
HTTP server answers `/health` for automated monitoring, and gossamer/panll
consumers can read the `static_analysis` capability description to confirm the
service identity.

The JSON manifest mirrors the Idris-aligned semantics under
`boj-server/src/interface/abi/Groove.idr` and the shared `gossamer/schema`
definitions, so every consumer (Gossamer, PanLL, Hypatia, or Burble) sees the
same capability vocabulary and can negotiate the link with confidence.

## Gossamer + Burble PanLL

When Gossamer (or a Burble-powered PanLL UI) discovers panic-attack via groove,
PanLL panels can auto-bind the static analysis service into PanLL’s event-chain
flows. Those panels load the exported `panll.event-chain.v0` artifacts documented
here, referencing the same VeriSimDB snapshot that supplies every proof and
benchmark baseline. VeriSimDB acts as the foundation dependency so the historical
timeline that PanLL renders stays aligned with the grooved manifest even after
panic-attack exits.
