// SPDX-License-Identifier: PMPL-1.0-or-later

//! Ambush execution: run a target program while applying ambient stressors.

mod timeline;

pub use timeline::{load_timeline_with_default, TimelinePlan};

use crate::signatures::SignatureEngine;
use crate::types::*;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

struct StressHandle {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    peak_memory: Arc<AtomicU64>,
}

impl StressHandle {
    fn stop(self) -> u64 {
        self.stop.store(true, Ordering::SeqCst);
        for handle in self.threads {
            let _ = handle.join();
        }
        self.peak_memory.load(Ordering::Relaxed)
    }
}

pub fn execute(config: AttackConfig) -> Result<Vec<AttackResult>> {
    let mut results = Vec::new();

    for program in &config.target_programs {
        for axis in &config.axes {
            println!(
                "Ambushing {:?} on axis {:?} (intensity: {:?}, duration: {:?})",
                program, axis, config.intensity, config.duration
            );

            let args = args_for_axis(&config, *axis);
            let start = Instant::now();

            let stress = start_stressor(*axis, config.intensity, config.duration);
            let output = run_program_with_deadline(program, &args, config.duration)?;
            let peak_memory = stress.stop();

            let duration = start.elapsed();
            let exit_code = output.status.code();
            let success = output.status.success();

            let mut crashes = Vec::new();
            if !success {
                crashes.push(crash_from_output(&output));
            }

            let signatures_detected = if !crashes.is_empty() {
                let engine = SignatureEngine::new();
                crashes
                    .iter()
                    .flat_map(|crash| engine.detect_from_crash(crash))
                    .collect()
            } else {
                Vec::new()
            };

            results.push(AttackResult {
                program: program.clone(),
                axis: *axis,
                success,
                skipped: false,
                skip_reason: None,
                exit_code,
                duration,
                peak_memory,
                crashes,
                signatures_detected,
            });
        }
    }

    Ok(results)
}

pub fn execute_timeline(
    mut config: AttackConfig,
    timeline: &TimelinePlan,
) -> Result<(Vec<AttackResult>, TimelineReport)> {
    let program = timeline
        .program
        .clone()
        .or_else(|| config.target_programs.first().cloned())
        .ok_or_else(|| anyhow::anyhow!("no program specified for ambush timeline"))?;
    config.target_programs = vec![program.clone()];

    let timeline_start = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let reports: Arc<Mutex<Vec<TimelineEventReport>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for event in &timeline.events {
        let event = event.clone();
        let stop = stop.clone();
        let reports = reports.clone();
        let handle = thread::spawn(move || {
            if wait_until(timeline_start + event.start_offset, &stop) {
                let stress = start_stressor(event.axis, event.intensity, event.duration);
                let deadline = Instant::now() + event.duration;
                while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(25));
                }
                let peak_memory = stress.stop();
                let mut reports = reports.lock().unwrap_or_else(|e| e.into_inner());
                reports.push(TimelineEventReport {
                    id: event.id,
                    axis: event.axis,
                    start_offset: event.start_offset,
                    duration: event.duration,
                    intensity: event.intensity,
                    args: event.args,
                    peak_memory: if event.axis == AttackAxis::Memory {
                        Some(peak_memory)
                    } else {
                        None
                    },
                    ran: true,
                });
            } else {
                let mut reports = reports.lock().unwrap_or_else(|e| e.into_inner());
                reports.push(TimelineEventReport {
                    id: event.id,
                    axis: event.axis,
                    start_offset: event.start_offset,
                    duration: event.duration,
                    intensity: event.intensity,
                    args: event.args,
                    peak_memory: None,
                    ran: false,
                });
            }
        });
        handles.push(handle);
    }

    let start = Instant::now();
    let output = run_program_with_deadline(&program, &config.common_args, timeline.duration)?;
    stop.store(true, Ordering::SeqCst);
    for handle in handles {
        let _ = handle.join();
    }

    let duration = start.elapsed();
    let exit_code = output.status.code();
    let success = output.status.success();

    let mut crashes = Vec::new();
    if !success {
        crashes.push(crash_from_output(&output));
    }

    let signatures_detected = if !crashes.is_empty() {
        let engine = SignatureEngine::new();
        crashes
            .iter()
            .flat_map(|crash| engine.detect_from_crash(crash))
            .collect()
    } else {
        Vec::new()
    };

    let event_reports = {
        let mut reports = reports.lock().unwrap_or_else(|e| e.into_inner());
        reports.sort_by_key(|report| report.start_offset);
        reports.clone()
    };

    let peak_memory = event_reports
        .iter()
        .filter_map(|report| report.peak_memory)
        .max()
        .unwrap_or(0);

    let attack_results = vec![AttackResult {
        program,
        axis: AttackAxis::Time,
        success,
        skipped: false,
        skip_reason: None,
        exit_code,
        duration,
        peak_memory,
        crashes,
        signatures_detected,
    }];

    Ok((
        attack_results,
        TimelineReport {
            duration: timeline.duration,
            events: event_reports,
        },
    ))
}

fn args_for_axis(config: &AttackConfig, axis: AttackAxis) -> Vec<String> {
    let mut args = config.common_args.clone();
    if let Some(axis_args) = config.axis_args.get(&axis) {
        args.extend(axis_args.clone());
    }
    args
}

fn wait_until(target: Instant, stop: &AtomicBool) -> bool {
    while Instant::now() < target {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
    !stop.load(Ordering::Relaxed)
}

fn start_stressor(axis: AttackAxis, intensity: IntensityLevel, duration: Duration) -> StressHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let peak_memory = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + duration;

    let threads = match axis {
        AttackAxis::Cpu => spawn_cpu_stress(stop.clone(), deadline, intensity),
        AttackAxis::Memory => {
            spawn_memory_stress(stop.clone(), deadline, intensity, peak_memory.clone())
        }
        AttackAxis::Disk => spawn_disk_stress(stop.clone(), deadline, intensity),
        AttackAxis::Network => spawn_network_stress(stop.clone(), deadline, intensity),
        AttackAxis::Concurrency => spawn_concurrency_stress(stop.clone(), deadline, intensity),
        AttackAxis::Time => Vec::new(),
    };

    StressHandle {
        stop,
        threads,
        peak_memory,
    }
}

fn spawn_cpu_stress(
    stop: Arc<AtomicBool>,
    deadline: Instant,
    intensity: IntensityLevel,
) -> Vec<JoinHandle<()>> {
    let workers = worker_count(intensity);
    (0..workers)
        .map(|_| {
            let stop = stop.clone();
            thread::spawn(move || {
                let mut acc: u64 = 0x1234_5678;
                while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    acc = acc.wrapping_mul(1664525).wrapping_add(1013904223);
                    std::hint::black_box(acc);
                }
            })
        })
        .collect()
}

fn spawn_concurrency_stress(
    stop: Arc<AtomicBool>,
    deadline: Instant,
    intensity: IntensityLevel,
) -> Vec<JoinHandle<()>> {
    let workers = (50.0 * intensity.multiplier()).max(1.0) as usize;
    (0..workers)
        .map(|_| {
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    std::hint::black_box(Instant::now());
                    thread::sleep(Duration::from_millis(5));
                }
            })
        })
        .collect()
}

fn spawn_memory_stress(
    stop: Arc<AtomicBool>,
    deadline: Instant,
    intensity: IntensityLevel,
    peak_memory: Arc<AtomicU64>,
) -> Vec<JoinHandle<()>> {
    vec![thread::spawn(move || {
        let target_bytes = (64_u64 * 1024 * 1024) * intensity.multiplier() as u64;
        let chunk = 4_u64 * 1024 * 1024;
        let mut allocated = 0_u64;
        let mut buffers: Vec<Vec<u8>> = Vec::new();

        while !stop.load(Ordering::Relaxed) && Instant::now() < deadline && allocated < target_bytes
        {
            let mut buf: Vec<u8> = Vec::new();
            if buf.try_reserve_exact(chunk as usize).is_err() {
                break;
            }
            buf.resize(chunk as usize, 0);
            buffers.push(buf);
            allocated += chunk;
            peak_memory.store(allocated, Ordering::Relaxed);
        }

        while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        drop(buffers);
    })]
}

fn spawn_disk_stress(
    stop: Arc<AtomicBool>,
    deadline: Instant,
    intensity: IntensityLevel,
) -> Vec<JoinHandle<()>> {
    vec![thread::spawn(move || {
        let root = std::env::temp_dir().join(format!("panic-attack-ambush-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        let files_per_cycle = (25.0 * intensity.multiplier()).max(1.0) as usize;
        let payload = vec![0xA5_u8; 128 * 1024];
        let mut counter = 0_u64;

        while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
            for _ in 0..files_per_cycle {
                if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }
                let path = root.join(format!("ambush-{}.bin", counter));
                counter = counter.wrapping_add(1);
                if let Ok(mut file) = File::create(&path) {
                    let _ = file.write_all(&payload);
                }
            }
        }

        let _ = fs::remove_dir_all(&root);
    })]
}

fn spawn_network_stress(
    stop: Arc<AtomicBool>,
    deadline: Instant,
    intensity: IntensityLevel,
) -> Vec<JoinHandle<()>> {
    let listener = TcpListener::bind("127.0.0.1:0");
    let Ok(listener) = listener else {
        return Vec::new();
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(_) => return Vec::new(),
    };
    let _ = listener.set_nonblocking(true);

    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        let mut buf = [0_u8; 1024];
        while !server_stop.load(Ordering::Relaxed) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let _ = stream.read(&mut buf);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let clients = (20.0 * intensity.multiplier()).max(1.0) as usize;
    let mut threads = Vec::with_capacity(clients + 1);
    threads.push(server);

    for _ in 0..clients {
        let stop = stop.clone();
        let addr = addr;
        threads.push(thread::spawn(move || {
            let payload = vec![0x5A_u8; 4096];
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                if let Ok(mut stream) = TcpStream::connect(addr) {
                    let _ = stream.write_all(&payload);
                }
                thread::sleep(Duration::from_millis(10));
            }
        }));
    }

    threads
}

fn worker_count(intensity: IntensityLevel) -> usize {
    let base = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (base as f64 * intensity.multiplier()).max(1.0) as usize
}

fn run_program_with_deadline(
    program: &PathBuf,
    args: &[String],
    duration: Duration,
) -> Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to execute program {}", program.display()))?;

    let start = Instant::now();
    loop {
        if let Some(_status) = child.try_wait()? {
            break;
        }
        if start.elapsed() >= duration {
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    Ok(child.wait_with_output()?)
}

fn crash_from_output(output: &Output) -> CrashReport {
    CrashReport {
        timestamp: chrono::Utc::now().to_rfc3339(),
        signal: extract_signal(&output.stderr),
        backtrace: extract_backtrace(&output.stderr),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
    }
}

fn extract_signal(stderr: &[u8]) -> Option<String> {
    let stderr_str = String::from_utf8_lossy(stderr);
    if stderr_str.contains("SIGSEGV") {
        Some("SIGSEGV".to_string())
    } else if stderr_str.contains("SIGABRT") {
        Some("SIGABRT".to_string())
    } else if stderr_str.contains("SIGILL") {
        Some("SIGILL".to_string())
    } else {
        None
    }
}

fn extract_backtrace(stderr: &[u8]) -> Option<String> {
    let stderr_str = String::from_utf8_lossy(stderr);
    if stderr_str.contains("backtrace") || stderr_str.contains("stack backtrace") {
        Some(stderr_str.to_string())
    } else {
        None
    }
}
