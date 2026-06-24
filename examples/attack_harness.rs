// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Attack harness for exercising panic-attack assault flags.

use clap::Parser;
use std::fs::{self, File};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "attack-harness")]
struct Args {
    /// CPU work iterations
    #[arg(long)]
    iterations: Option<u64>,

    /// Allocate memory in megabytes
    #[arg(long = "allocate-mb")]
    allocate_mb: Option<u64>,

    /// Write many small files
    #[arg(long = "write-files")]
    write_files: Option<u64>,

    /// Create many local connections
    #[arg(long)]
    connections: Option<u64>,

    /// Spawn many threads
    #[arg(long)]
    threads: Option<u64>,
}

fn main() {
    let args = Args::parse();

    if let Some(iterations) = args.iterations {
        cpu_work(iterations);
        return;
    }
    if let Some(allocate_mb) = args.allocate_mb {
        memory_work(allocate_mb);
        return;
    }
    if let Some(write_files) = args.write_files {
        disk_work(write_files);
        return;
    }
    if let Some(connections) = args.connections {
        network_work(connections);
        return;
    }
    if let Some(threads) = args.threads {
        concurrency_work(threads);
        return;
    }

    eprintln!(
        "No attack flag provided. Use --iterations, --allocate-mb, --write-files, --connections, or --threads."
    );
    std::process::exit(2);
}

fn cpu_work(iterations: u64) {
    let mut acc = 0u64;
    for i in 0..iterations {
        acc = acc.wrapping_add(i.rotate_left(7));
    }
    println!("CPU work complete: {}", acc);
}

fn memory_work(allocate_mb: u64) {
    let bytes = allocate_mb.saturating_mul(1024 * 1024) as usize;
    let mut buffer = vec![0u8; bytes];
    for (idx, val) in buffer.iter_mut().enumerate() {
        *val = (idx % 256) as u8;
    }
    let checksum: u64 = buffer.iter().map(|b| *b as u64).sum();
    println!(
        "Memory allocation complete: {} bytes, checksum {}",
        bytes, checksum
    );
}

fn disk_work(write_files: u64) {
    let dir = std::env::temp_dir().join("panic-attack-harness");
    if let Err(err) = fs::create_dir_all(&dir) {
        eprintln!("Failed to create temp dir: {}", err);
        std::process::exit(1);
    }

    let payload = vec![b'x'; 4096];
    for i in 0..write_files {
        let path = dir.join(format!("file-{}.bin", i));
        match File::create(&path).and_then(|mut file| file.write_all(&payload)) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("Failed to write {}: {}", path.display(), err);
                std::process::exit(1);
            }
        }
    }

    let _ = fs::remove_dir_all(&dir);
    println!("Disk work complete: {} files", write_files);
}

fn network_work(connections: u64) {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Failed to bind listener: {}", err);
            std::process::exit(1);
        }
    };
    let addr = listener.local_addr().expect("listener has addr");
    let handle = thread::spawn(move || {
        for _ in 0..connections {
            let _ = listener.accept();
        }
    });

    let mut sockets = Vec::new();
    for _ in 0..connections {
        if let Ok(stream) = TcpStream::connect(addr) {
            sockets.push(stream);
        }
    }

    let _ = handle.join();
    println!("Network work complete: {} connections", sockets.len());
}

fn concurrency_work(threads: u64) {
    let threads = threads.max(1);
    let start = Instant::now();
    let mut handles = Vec::new();
    for i in 0..threads {
        handles.push(thread::spawn(move || {
            let mut acc = 0u64;
            for j in 0..10_000 {
                acc = acc.wrapping_add(j ^ i);
            }
            acc
        }));
    }

    let mut total = 0u64;
    for handle in handles {
        if let Ok(val) = handle.join() {
            total = total.wrapping_add(val);
        }
    }
    println!(
        "Concurrency work complete: {} threads in {:.2?} (checksum {})",
        threads,
        start.elapsed(),
        total
    );
}
