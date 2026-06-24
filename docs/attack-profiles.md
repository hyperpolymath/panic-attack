<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->
# Attack Profiles

Attack profiles let you pass custom arguments to target programs during assaults. Profiles are
JSON or YAML and can supply common arguments, axis-specific arguments, and probe mode.

Ambush runs also accept profiles. The arguments are forwarded to the target program while the
ambient stressors run in parallel.

## Schema

- `common_args`: list of arguments added to every attack invocation.
- `axes`: map of axis names to argument lists.
- `probe_mode`: `auto`, `always`, or `never`.

Axis keys: `cpu`, `memory`, `disk`, `network`, `concurrency`, `time`.

## JSON example

```
{
  "common_args": ["--config", "cfg.toml"],
  "axes": {
    "cpu": ["--iterations", "5000"],
    "memory": ["--allocate-mb", "512"]
  },
  "probe_mode": "always"
}
```

## YAML example

```
common_args:
  - --config
  - cfg.toml
axes:
  cpu:
    - --iterations
    - "5000"
  memory:
    - --allocate-mb
    - "512"
probe_mode: always
```

## CLI usage

```
panic-attack assault ./my-program --profile profiles/attack-profile.example.json
panic-attack assault ./my-program --arg --config --arg cfg.toml
panic-attack assault ./my-program --axis-arg cpu=--iterations --axis-arg cpu=5000
panic-attack assault ./my-program --probe always
```
