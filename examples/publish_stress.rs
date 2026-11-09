// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Experiments for `docs/design/GENERATION-PUBLISH.adoc`.
//!
//! Three ways to write the report set `S.json`, `S.kyaml`,
//! `S.attestation.json` are compared:
//!
//! - `inplace`: `fs::write` each file (main today);
//! - `perfile`: temp file + rename for each file (the withdrawn
//!   `atomic_write` approach);
//! - `genset`: `panic_attack::publish` generation directories.
//!
//! ```text
//! cargo run --release --example publish_stress -- race  <mode> <writers> <readers> <iters>
//! cargo run --release --example publish_stress -- crash <mode> <trials>
//! cargo run --release --example publish_stress -- bench <mode> <bytes> <iters>
//! ```
//!
//! Every count printed is measured; none is estimated.

use panic_attack::publish::{self, Generation, Options};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const NAMES: [&str; 3] = ["S.json", "S.kyaml", "S.attestation.json"];
const PAD: usize = 256 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    let n = |i: usize| a(i).parse::<u64>().expect("number");
    match a(0) {
        "race" => race(a(1), n(2), n(3), n(4)),
        "crash" => crash(a(1), n(2)),
        "bench" => bench(a(1), n(2) as usize, n(3)),
        "writer" => writer(a(1), Path::new(a(2)), a(3), n(4), PAD),
        "reader" => reader(a(1), Path::new(a(2)), n(3)),
        _ => eprintln!("usage: see the module comment"),
    }
}

fn set_for(run: &str, pad: usize) -> [(String, Vec<u8>); 3] {
    let json = format!("{{\"pad\":\"{}\",\"run\":\"{run}\"}}\n", "x".repeat(pad));
    let sha = hex::encode(Sha256::digest(json.as_bytes()));
    let kyaml = format!(
        "{{\n  pad: \"{}\",\n  run: \"{run}\",\n}}\n",
        "x".repeat(pad)
    );
    let sidecar = format!("{{\"report_sha256\":\"{sha}\",\"run\":\"{run}\"}}\n");
    [
        (NAMES[0].into(), json.into_bytes()),
        (NAMES[1].into(), kyaml.into_bytes()),
        (NAMES[2].into(), sidecar.into_bytes()),
    ]
}

fn write_set(mode: &str, dir: &Path, run: &str, pad: usize) {
    let files = set_for(run, pad);
    match mode {
        "inplace" => {
            for (name, bytes) in &files {
                fs::write(dir.join(name), bytes).unwrap();
            }
        }
        "perfile" => {
            for (name, bytes) in &files {
                let tmp = dir.join(format!(".{name}.{}.tmp", publish::new_id().unwrap()));
                let mut f = fs::File::create_new(&tmp).unwrap();
                std::io::Write::write_all(&mut f, bytes).unwrap();
                f.sync_all().unwrap();
                fs::rename(&tmp, dir.join(name)).unwrap();
            }
        }
        "genset" => {
            let mut g = Generation::begin(&dir.join("S.json"), publish::new_id().unwrap()).unwrap();
            for (name, bytes) in &files {
                g.write(name, bytes).unwrap();
            }
            g.publish(&Options::default()).unwrap();
        }
        other => panic!("unknown mode {other}"),
    }
}

fn writer(mode: &str, dir: &Path, id: &str, iters: u64, pad: usize) {
    for i in 0..iters {
        write_set(mode, dir, &format!("{id}-{i}"), pad);
    }
}

#[derive(Default, Debug)]
struct Tally {
    reads: u64,
    partial: u64,
    torn: u64,
    missing: u64,
}

/// Classify one set of three byte strings.
fn classify(files: &[Vec<u8>], t: &mut Tally) {
    t.reads += 1;
    let json: Option<serde_json::Value> = serde_json::from_slice(&files[0]).ok();
    let side: Option<serde_json::Value> = serde_json::from_slice(&files[2]).ok();
    let kyaml_ok = files[1].ends_with(b"}\n");
    let (Some(json), Some(side), true) = (json, side, kyaml_ok) else {
        t.partial += 1;
        return;
    };
    let kyaml = String::from_utf8_lossy(&files[1]);
    let run = json["run"].as_str().unwrap_or("");
    let sha = hex::encode(Sha256::digest(&files[0]));
    if side["run"] != run
        || side["report_sha256"] != sha.as_str()
        || !kyaml.contains(&format!("run: \"{run}\""))
    {
        t.torn += 1;
    }
}

fn read_once(mode: &str, dir: &Path, t: &mut Tally) {
    if mode == "genset-consistent" {
        match publish::read_consistent(&publish::root_for(&dir.join("S.json"))) {
            Ok(Some((_, files))) => {
                let v: Vec<Vec<u8>> = NAMES.iter().map(|n| files[*n].clone()).collect();
                classify(&v, t)
            }
            Ok(None) => {}
            Err(_) => t.missing += 1,
        }
        return;
    }
    let mut v = Vec::new();
    for name in NAMES {
        match fs::read(dir.join(name)) {
            Ok(b) => v.push(b),
            Err(_) => {
                t.missing += 1;
                return;
            }
        }
    }
    classify(&v, t);
}

fn reader(mode: &str, dir: &Path, millis: u64) {
    let mut t = Tally::default();
    let end = Instant::now() + Duration::from_millis(millis);
    while Instant::now() < end && !dir.join(".done").exists() {
        read_once(mode, dir, &mut t);
    }
    println!("{} {} {} {}", t.reads, t.partial, t.torn, t.missing);
}

fn me() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn race(mode: &str, writers: u64, readers: u64, iters: u64) {
    let dir = tempfile::tempdir().unwrap();
    write_set(mode, dir.path(), "seed-0", PAD);
    let start = Instant::now();
    let ws: Vec<Child> = (0..writers)
        .map(|w| {
            Command::new(me())
                .args(["writer", mode])
                .arg(dir.path())
                .args([format!("w{w}"), iters.to_string()])
                .spawn()
                .unwrap()
        })
        .collect();
    // Readers of the plain paths, and for genset also manifest readers.
    let mut read_modes = vec![mode.to_string()];
    if mode == "genset" {
        read_modes.push("genset-consistent".into());
    }
    let mut rs = Vec::new();
    for rm in &read_modes {
        for _ in 0..readers {
            rs.push((
                rm.clone(),
                Command::new(me())
                    .args(["reader", rm])
                    .arg(dir.path())
                    .arg("120000")
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap(),
            ));
        }
    }
    for mut w in ws {
        assert!(w.wait().unwrap().success());
    }
    let wall = start.elapsed();
    fs::write(dir.path().join(".done"), b"").unwrap();
    for rm in &read_modes {
        let mut sum = [0u64; 4];
        for (m, r) in rs.iter_mut().filter(|(m, _)| m == rm) {
            let _ = m;
            let out = r.stdout.take().unwrap();
            let s = std::io::read_to_string(out).unwrap();
            for (i, x) in s.split_whitespace().enumerate() {
                sum[i] += x.parse::<u64>().unwrap();
            }
        }
        for (_, r) in rs.iter_mut().filter(|(m, _)| m == rm) {
            r.wait().unwrap();
        }
        println!(
            "race mode={mode} readers-of={rm} writers={writers} iters={iters} \
             writer_wall_ms={} reads={} partial={} torn={} missing={}",
            wall.as_millis(),
            sum[0],
            sum[1],
            sum[2],
            sum[3]
        );
    }
    let mut t = Tally::default();
    read_once(mode, dir.path(), &mut t);
    println!(
        "race mode={mode} final-state partial={} torn={} missing={}",
        t.partial, t.torn, t.missing
    );
}

fn crash(mode: &str, trials: u64) {
    let mut bad = Tally::default();
    let mut consistent_bad = 0u64;
    for trial in 0..trials {
        let dir = tempfile::tempdir().unwrap();
        write_set(mode, dir.path(), "seed-0", PAD);
        let mut child = Command::new(me())
            .args(["writer", mode])
            .arg(dir.path())
            .args([format!("c{trial}"), "1000".into()])
            .spawn()
            .unwrap();
        // Kill somewhere inside the write loop: 1–40 ms in.
        std::thread::sleep(Duration::from_micros(1000 + (trial * 7919) % 39000));
        child.kill().unwrap();
        child.wait().unwrap();
        read_once(mode, dir.path(), &mut bad);
        if mode == "genset" {
            match publish::read_consistent(&publish::root_for(&dir.path().join("S.json"))) {
                Ok(Some(_)) => {}
                _ => consistent_bad += 1,
            }
        }
    }
    println!(
        "crash mode={mode} trials={trials} after-kill: partial={} torn={} missing={}{}",
        bad.partial,
        bad.torn,
        bad.missing,
        if mode == "genset" {
            format!(" manifest-read-failures={consistent_bad}")
        } else {
            String::new()
        }
    );
}

fn bench(mode: &str, bytes: usize, iters: u64) {
    let dir = tempfile::tempdir().unwrap();
    let mut samples = Vec::with_capacity(iters as usize);
    for i in 0..iters {
        let t0 = Instant::now();
        write_set(mode, dir.path(), &format!("b-{i}"), bytes);
        samples.push(t0.elapsed().as_micros() as u64);
    }
    samples.sort_unstable();
    let pct = |p: f64| samples[((samples.len() - 1) as f64 * p) as usize];
    println!(
        "bench mode={mode} pad_bytes={bytes} iters={iters} p50_us={} p90_us={} max_us={}",
        pct(0.5),
        pct(0.9),
        samples[samples.len() - 1]
    );
}
