---------------------------- MODULE GenerationPublish ----------------------------
\* SPDX-License-Identifier: MPL-2.0
\* SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
\*
\* The generation-publish protocol of src/publish.rs, for TLC.
\*
\* PROOF-POLICY section 4 exception: TLA+ model checking of a concurrency
\* protocol, the policy's worked example. The obligation is a property of
\* interleavings of several processes and of crashes between file-system
\* operations; neither Creusot nor Verus states that. A finite check is
\* reported as TESTED with the bounds in the .cfg files, never as PROVEN.
\* tests/publish_model.rs checks the same model independently in Rust.
\*
\* Each step is one file-system operation of the code. Writer w's generation
\* id is w, so ids order generations by start time and the interleavings
\* decide who finishes first. A crash is SIGKILL: the process stops and the
\* kernel releases its lock. Power loss and fsync ordering are out of scope.

EXTENDS Naturals, FiniteSets

CONSTANTS
    Writers,    \* writer ids, e.g. 1..3
    NFiles,     \* files per generation, mirrored one at a time
    Keep,       \* complete generations kept besides the current one
    Crashes,    \* TRUE: a writer may crash at any step
    Retry,      \* TRUE: the reader retries when its generation vanished
    MaxRetries,
    Mutant      \* "none", or one deliberate defect (see the Mutant* configs)

VARIABLES gen, pc, mi, current, lock, mirror, rpc, rgen, retries

vars == <<gen, pc, mi, current, lock, mirror, rpc, rgen, retries>>

None == 0
Files == 1..NFiles

TypeOK ==
    /\ gen \in [Writers -> {"absent", "partial", "complete", "removed"}]
    /\ pc \in [Writers -> {"start", "writing", "renamed", "locked", "mirroring",
                           "superseded", "collected", "done", "crashed", "failed"}]
    /\ mi \in [Writers -> 0..NFiles]
    /\ current \in Writers \cup {None}
    /\ lock \in Writers \cup {None}
    /\ mirror \in [Files -> Writers \cup {None}]
    /\ rpc \in {"idle", "got", "missed", "ok", "failed"}
    /\ rgen \in Writers \cup {None}
    /\ retries \in 0..MaxRetries

Init ==
    /\ gen = [w \in Writers |-> "absent"]
    /\ pc = [w \in Writers |-> "start"]
    /\ mi = [w \in Writers |-> 0]
    /\ current = None
    /\ lock = None
    /\ mirror = [f \in Files |-> None]
    /\ rpc = "idle"
    /\ rgen = None
    /\ retries = 0

\* Collect: remove complete generations older than the current one, except
\* the Keep newest of them.
Collected(g, cur) ==
    LET older == {h \in Writers : h < cur /\ g[h] = "complete"}
        doomed == {h \in older : Cardinality({k \in older : k > h}) >= Keep}
    IN [h \in Writers |->
          IF h \in doomed \/ (Mutant = "collectcurrent" /\ h = cur)
          THEN "removed" ELSE g[h]]

Begin(w) ==
    /\ pc[w] = "start"
    /\ gen' = [gen EXCEPT ![w] = "partial"]
    /\ pc' = [pc EXCEPT ![w] = "writing"]
    \* Mutant: publish the generation while it is still partial.
    /\ current' = IF Mutant = "swapbeforecomplete" THEN w ELSE current
    /\ UNCHANGED <<mi, lock, mirror, rpc, rgen, retries>>

\* Rename <id>.partial to <id>. Fails if collect removed the partial
\* generation under a writer that stalled past the grace period.
Rename(w) ==
    /\ pc[w] = "writing"
    /\ IF gen[w] = "removed"
       THEN /\ pc' = [pc EXCEPT ![w] = "failed"]
            /\ UNCHANGED gen
       ELSE /\ gen' = [gen EXCEPT ![w] = "complete"]
            /\ pc' = [pc EXCEPT ![w] = "renamed"]
    /\ UNCHANGED <<mi, current, lock, mirror, rpc, rgen, retries>>

Acquire(w) ==
    /\ pc[w] = "renamed"
    /\ lock = None
    /\ lock' = w
    /\ pc' = [pc EXCEPT ![w] = "locked"]
    /\ UNCHANGED <<gen, mi, current, mirror, rpc, rgen, retries>>

\* Under the lock: refuse if a newer generation is current, else move CURRENT.
Swap(w) ==
    /\ pc[w] = "locked"
    /\ IF Mutant /= "nosupersede" /\ current /= None /\ current > w
       THEN /\ gen' = [gen EXCEPT ![w] = "removed"]
            /\ pc' = [pc EXCEPT ![w] = "superseded"]
            /\ UNCHANGED current
       ELSE /\ current' = w
            /\ pc' = [pc EXCEPT ![w] = "mirroring"]
            /\ UNCHANGED gen
    /\ UNCHANGED <<mi, lock, mirror, rpc, rgen, retries>>

MirrorStep(w) ==
    /\ pc[w] = "mirroring"
    /\ mi[w] < NFiles
    /\ mirror' = [mirror EXCEPT ![mi[w] + 1] = w]
    /\ mi' = [mi EXCEPT ![w] = mi[w] + 1]
    /\ UNCHANGED <<gen, pc, current, lock, rpc, rgen, retries>>

Collect(w) ==
    /\ \/ pc[w] = "mirroring" /\ mi[w] = NFiles
       \/ pc[w] = "superseded"
    /\ gen' = IF current = None THEN gen ELSE Collected(gen, current)
    /\ pc' = [pc EXCEPT ![w] = "collected"]
    /\ UNCHANGED <<mi, current, lock, mirror, rpc, rgen, retries>>

Release(w) ==
    /\ pc[w] = "collected"
    /\ lock' = None
    /\ pc' = [pc EXCEPT ![w] = "done"]
    /\ UNCHANGED <<gen, mi, current, mirror, rpc, rgen, retries>>

Crash(w) ==
    /\ Crashes
    /\ pc[w] \notin {"done", "crashed", "failed"}
    /\ pc' = [pc EXCEPT ![w] = "crashed"]
    /\ lock' = IF lock = w THEN None ELSE lock
    /\ UNCHANGED <<gen, mi, current, mirror, rpc, rgen, retries>>

\* Grace-period removal of a partial generation, crashed or merely stalled.
GcPartial(w) ==
    /\ gen[w] = "partial"
    /\ gen' = [gen EXCEPT ![w] = "removed"]
    /\ UNCHANGED <<pc, mi, current, lock, mirror, rpc, rgen, retries>>

\* The lock-free manifest reader: read CURRENT, open its generation, and on
\* "not found" start again only if CURRENT has moved.
ReadPointer ==
    /\ rpc = "idle"
    /\ current /= None
    /\ rpc' = "got"
    /\ rgen' = current
    /\ UNCHANGED <<gen, pc, mi, current, lock, mirror, retries>>

OpenGeneration ==
    /\ rpc = "got"
    /\ rpc' = IF gen[rgen] = "complete" THEN "ok" ELSE "missed"
    /\ UNCHANGED <<gen, pc, mi, current, lock, mirror, rgen, retries>>

Recheck ==
    /\ rpc = "missed"
    /\ IF Retry /\ current /= rgen /\ retries < MaxRetries
       THEN /\ rpc' = "idle"
            /\ retries' = retries + 1
       ELSE /\ rpc' = "failed"
            /\ UNCHANGED retries
    /\ UNCHANGED <<gen, pc, mi, current, lock, mirror, rgen>>

Next ==
    \/ \E w \in Writers :
          Begin(w) \/ Rename(w) \/ Acquire(w) \/ Swap(w) \/ MirrorStep(w)
          \/ Collect(w) \/ Release(w) \/ Crash(w) \/ GcPartial(w)
    \/ ReadPointer \/ OpenGeneration \/ Recheck

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* P1: CURRENT only ever names a complete generation.
CurrentIsComplete == current /= None => gen[current] = "complete"

\* P2: CURRENT never moves to an older generation (an action property).
CurrentMonotone == [][current /= None => current' /= None /\ current' >= current]_vars

\* P3: the manifest reader never fails.
ReaderNeverFails == rpc /= "failed"

\* P4: once no writer runs, every mirror names the current generation.
\* Expected to FAIL when Crashes is TRUE (the documented mirror limit).
Quiet == lock = None /\ \A w \in Writers : pc[w] \in {"start", "done", "crashed", "failed"}
MirrorsConsistentWhenQuiet ==
    (Quiet /\ current /= None) => \A f \in Files : mirror[f] = current
=============================================================================
