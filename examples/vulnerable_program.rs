// SPDX-License-Identifier: MPL-2.0

//! Example vulnerable program for testing panic-attacker
//!
//! This program contains intentional bugs for demonstration purposes.
//! DO NOT use this code in production!

#![allow(clippy::unnecessary_literal_unwrap)]
#![allow(static_mut_refs)]

use std::env;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <test-name>", args[0]);
        println!("Tests: panic, oom, deadlock, race, unwrap");
        return;
    }

    match args[1].as_str() {
        "panic" => test_panic(),
        "oom" => test_oom(),
        "deadlock" => test_deadlock(),
        "race" => test_race(),
        "unwrap" => test_unwrap(),
        _ => println!("Unknown test: {}", args[1]),
    }
}

/// Test: Panic on invalid input
fn test_panic() {
    println!("Testing panic...");
    let input = "not a number";
    let _num: i32 = input.parse().unwrap(); // Intentional panic
}

/// Test: Out of memory
fn test_oom() {
    println!("Testing OOM...");
    let mut vecs = Vec::new();
    loop {
        let v = vec![0u8; 1024 * 1024]; // 1MB allocations
        vecs.push(v);
        println!("Allocated {} MB", vecs.len());
    }
}

/// Test: Deadlock
fn test_deadlock() {
    println!("Testing deadlock...");

    let mutex1 = Arc::new(Mutex::new(0));
    let mutex2 = Arc::new(Mutex::new(0));

    let m1_clone = mutex1.clone();
    let m2_clone = mutex2.clone();

    let handle1 = thread::spawn(move || {
        let _g1 = m1_clone.lock().unwrap();
        println!("Thread 1: locked mutex1");
        thread::sleep(Duration::from_millis(100));
        let _g2 = m2_clone.lock().unwrap(); // Will deadlock here
        println!("Thread 1: locked mutex2");
    });

    let handle2 = thread::spawn(move || {
        let _g2 = mutex2.lock().unwrap();
        println!("Thread 2: locked mutex2");
        thread::sleep(Duration::from_millis(100));
        let _g1 = mutex1.lock().unwrap(); // Will deadlock here
        println!("Thread 2: locked mutex1");
    });

    handle1.join().unwrap();
    handle2.join().unwrap();
}

/// Test: Data race (requires unsafe)
fn test_race() {
    println!("Testing data race...");

    static mut COUNTER: i32 = 0;

    let handles: Vec<_> = (0..10)
        .map(|i| {
            thread::spawn(move || {
                for _ in 0..1000 {
                    unsafe {
                        COUNTER += 1; // Data race!
                    }
                }
                println!("Thread {} finished", i);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    unsafe {
        println!("Final counter: {}", COUNTER);
    }
}

/// Test: Multiple unwraps
fn test_unwrap() {
    println!("Testing unwraps...");

    let maybe_value: Option<i32> = None;
    let value = maybe_value.unwrap(); // Will panic
    println!("Value: {}", value);
}
