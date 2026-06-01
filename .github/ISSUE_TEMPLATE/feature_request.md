---
name: Feature request
about: Propose a new detector, sub-command, output schema, or integration for panic-attack
title: ''
labels: enhancement
assignees: ''

---

**What problem does this solve?**
Describe the gap or pain point — what does panic-attack currently miss / get wrong / make awkward? Cite a real-world finding or workflow where possible.

**Proposed solution**
What would the new behaviour look like? If this is a new detector, what does it match, and what's the false-positive avoidance plan? If a new sub-command, what's its surface (`panic-attack <name> [args]`)?

**Alternatives considered**
- Could this be expressed by an existing detector + classification?
- Could it live downstream in hypatia (rule layer) instead of panic-attack (detector layer)?
- Could `audits/assail-classifications.a2ml` cover it via classification entries?

**Impact / scope**
- Estate repos likely to benefit:
- Schema / output changes (would this bump `schema_version`?):
- Cross-repo wiring (hypatia#358 fact-source consumption, bridge-classifier downstream, etc.):

**Additional context**
Links to motivating findings, related issues, or upstream tooling that informs the design.
