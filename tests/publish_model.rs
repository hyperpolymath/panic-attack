// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Exhaustive explicit-state check of the generation-publish protocol in
//! `src/publish.rs` (design: `docs/design/GENERATION-PUBLISH.adoc`).
//!
//! This is an abstract model, not the code: each step below stands for one
//! filesystem operation the code performs, and every interleaving of up to
//! three writers and one reader is explored, with a crash (SIGKILL: the
//! process stops, the kernel drops its lock) allowed at every writer step.
//! It checks process crashes only. Power loss and fsync ordering are out of
//! scope here.
//!
//! Invariants checked in every reachable state:
//! - P1: `CURRENT` only ever names a complete generation.
//! - P2: `CURRENT` never moves to an older generation.
//! - P3: the manifest reader never returns a generation that is not
//!   complete, and never fails while `CURRENT` names a readable one.
//! - P4 (expected to FAIL with crashes, see the design note): once no writer
//!   is running, the top-level mirrors all name the current generation.

use std::collections::{HashSet, VecDeque};

const FILES: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Gen {
    Absent,
    Partial,
    Complete,
    Removed,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Pc {
    Start,
    Writing,
    Renamed,
    Locked,
    Swapped,
    Mirrored(u8),
    Superseded,
    Collected,
    Done,
    Crashed,
    /// Its partial generation was collected under it, so its next write or
    /// rename failed with "not found" and it exited with an error.
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Reader {
    Idle,
    Got(u8),
    Missed(u8),
    Ok(u8),
    Failed,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct State {
    gens: Vec<Gen>,
    pc: Vec<Pc>,
    current: Option<u8>,
    lock: Option<u8>,
    mirrors: [Option<u8>; FILES],
    reader: Reader,
    retries: u8,
}

struct Config {
    writers: u8,
    keep: usize,
    crashes: bool,
    reader_retries: bool,
    /// A deliberate defect, to show the invariants can fail (see the
    /// `mutant_*` tests). `None` is the protocol as implemented.
    mutant: Option<Mutant>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mutant {
    /// Move `CURRENT` without comparing generation ids.
    NoSupersedeCheck,
    /// Swap the pointer before renaming `.partial` to complete.
    SwapBeforeComplete,
    /// Collect the current generation along with the older ones.
    CollectCurrent,
}

/// Writer `i` has generation id `i`: ids order generations by start time,
/// and the interleavings decide who finishes first.
fn successors(s: &State, c: &Config) -> Vec<State> {
    let mut out = Vec::new();
    for i in 0..c.writers {
        let w = i as usize;
        let mut n = s.clone();
        let step = match s.pc[w] {
            Pc::Start => {
                n.gens[w] = Gen::Partial;
                n.pc[w] = Pc::Writing;
                true
            }
            Pc::Writing => {
                if c.mutant == Some(Mutant::SwapBeforeComplete) && s.lock.is_none() {
                    // Publish while the generation is still partial.
                    n.current = Some(i);
                }
                if s.gens[w] == Gen::Removed {
                    n.pc[w] = Pc::Failed;
                } else {
                    n.gens[w] = Gen::Complete;
                    n.pc[w] = Pc::Renamed;
                }
                true
            }
            Pc::Renamed if s.lock.is_none() => {
                n.lock = Some(i);
                n.pc[w] = Pc::Locked;
                true
            }
            Pc::Locked => {
                if c.mutant != Some(Mutant::NoSupersedeCheck) && s.current.is_some_and(|g| g > i) {
                    n.gens[w] = Gen::Removed;
                    n.pc[w] = Pc::Superseded;
                } else {
                    n.current = Some(i);
                    n.pc[w] = Pc::Swapped;
                }
                true
            }
            Pc::Swapped => {
                n.mirrors[0] = Some(i);
                n.pc[w] = Pc::Mirrored(1);
                true
            }
            Pc::Mirrored(k) if (k as usize) < FILES => {
                n.mirrors[k as usize] = Some(i);
                n.pc[w] = Pc::Mirrored(k + 1);
                true
            }
            Pc::Mirrored(_) | Pc::Superseded => {
                collect(&mut n, c.keep, c.mutant == Some(Mutant::CollectCurrent));
                n.pc[w] = Pc::Collected;
                true
            }
            Pc::Collected => {
                n.lock = None;
                n.pc[w] = Pc::Done;
                true
            }
            _ => false,
        };
        if step {
            out.push(n);
        }
        if c.crashes && !matches!(s.pc[w], Pc::Done | Pc::Crashed | Pc::Failed) {
            let mut n = s.clone();
            n.pc[w] = Pc::Crashed;
            if n.lock == Some(i) {
                n.lock = None;
            }
            out.push(n);
        }
        // Grace-period removal of a partial generation. `collect` cannot tell
        // a crashed writer from one that has stalled past the grace period, so
        // a live writer's partial generation can be removed too.
        if s.gens[w] == Gen::Partial {
            let mut n = s.clone();
            n.gens[w] = Gen::Removed;
            out.push(n);
        }
    }
    // Reader.
    let mut n = s.clone();
    let reader_step = match s.reader {
        Reader::Idle => match s.current {
            Some(g) => {
                n.reader = Reader::Got(g);
                true
            }
            None => false,
        },
        Reader::Got(g) => {
            n.reader = if s.gens[g as usize] == Gen::Complete {
                Reader::Ok(g)
            } else {
                Reader::Missed(g)
            };
            true
        }
        Reader::Missed(g) => {
            n.reader = if c.reader_retries && s.current != Some(g) && s.retries < 3 {
                n.retries += 1;
                Reader::Idle
            } else {
                Reader::Failed
            };
            true
        }
        Reader::Ok(_) | Reader::Failed => false,
    };
    if reader_step {
        out.push(n);
    }
    out
}

fn collect(s: &mut State, keep: usize, also_current: bool) {
    if also_current {
        if let Some(g) = s.current {
            s.gens[g as usize] = Gen::Removed;
        }
    }
    let Some(current) = s.current else { return };
    let older: Vec<usize> = (0..s.gens.len())
        .filter(|&g| (g as u8) < current && s.gens[g] == Gen::Complete)
        .collect();
    let keep_from = older.len().saturating_sub(keep);
    for &g in &older[..keep_from] {
        s.gens[g] = Gen::Removed;
    }
}

#[derive(Debug, Default)]
struct Report {
    states: usize,
    p1: Option<State>,
    p2: Option<(State, State)>,
    p3: Option<State>,
    p4: Option<State>,
}

fn explore(c: &Config) -> Report {
    let w = c.writers as usize;
    let init = State {
        gens: vec![Gen::Absent; w],
        pc: vec![Pc::Start; w],
        current: None,
        lock: None,
        mirrors: [None; FILES],
        reader: Reader::Idle,
        retries: 0,
    };
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([init.clone()]);
    seen.insert(init);
    let mut r = Report::default();
    while let Some(s) = queue.pop_front() {
        r.states += 1;
        if let Some(g) = s.current {
            if s.gens[g as usize] != Gen::Complete && r.p1.is_none() {
                r.p1 = Some(s.clone());
            }
        }
        if s.reader == Reader::Failed && r.p3.is_none() {
            r.p3 = Some(s.clone());
        }
        let quiet = s.lock.is_none()
            && s.pc
                .iter()
                .all(|p| matches!(p, Pc::Done | Pc::Crashed | Pc::Failed | Pc::Start));
        if quiet
            && s.current.is_some()
            && s.mirrors.iter().any(|m| *m != s.current)
            && r.p4.is_none()
        {
            r.p4 = Some(s.clone());
        }
        for n in successors(&s, c) {
            if let (Some(a), Some(b)) = (s.current, n.current) {
                if b < a && r.p2.is_none() {
                    r.p2 = Some((s.clone(), n.clone()));
                }
            }
            if seen.insert(n.clone()) {
                queue.push_back(n);
            }
        }
    }
    r
}

#[test]
fn p1_p2_p3_hold_for_every_interleaving_with_crashes() {
    for keep in [0, 1] {
        for writers in [2, 3] {
            let r = explore(&Config {
                writers,
                keep,
                crashes: true,
                reader_retries: true,
                mutant: None,
            });
            eprintln!("writers={writers} keep={keep} states={}", r.states);
            assert!(r.p1.is_none(), "P1 violated: {:?}", r.p1);
            assert!(r.p2.is_none(), "P2 violated: {:?}", r.p2);
            assert!(r.p3.is_none(), "P3 violated: {:?}", r.p3);
        }
    }
}

#[test]
fn without_the_retry_a_reader_can_fail() {
    let r = explore(&Config {
        writers: 2,
        keep: 0,
        crashes: false,
        reader_retries: false,
        mutant: None,
    });
    assert!(r.p3.is_some(), "expected a P3 counterexample without retry");
}

#[test]
fn mirrors_are_consistent_when_quiet_without_crashes() {
    let r = explore(&Config {
        writers: 3,
        keep: 1,
        crashes: false,
        reader_retries: true,
        mutant: None,
    });
    assert!(r.p4.is_none(), "P4 violated: {:?}", r.p4);
}

#[test]
fn a_crash_can_leave_the_mirrors_torn() {
    let r = explore(&Config {
        writers: 2,
        keep: 1,
        crashes: true,
        reader_retries: true,
        mutant: None,
    });
    let s = r.p4.expect("expected the known P4 counterexample");
    eprintln!("P4 counterexample: {s:?}");
}

/// Each mutant breaks one step of the protocol. The checker must find a
/// counterexample for each, or the invariants above would prove nothing.
fn mutant(m: Mutant) -> Report {
    explore(&Config {
        writers: 2,
        keep: 1,
        crashes: true,
        reader_retries: true,
        mutant: Some(m),
    })
}

#[test]
fn mutant_without_the_supersede_check_moves_current_backwards() {
    assert!(mutant(Mutant::NoSupersedeCheck).p2.is_some());
}

#[test]
fn mutant_swapping_before_completion_points_at_a_partial_generation() {
    assert!(mutant(Mutant::SwapBeforeComplete).p1.is_some());
}

#[test]
fn mutant_collecting_the_current_generation_breaks_the_pointer() {
    assert!(mutant(Mutant::CollectCurrent).p1.is_some());
}
