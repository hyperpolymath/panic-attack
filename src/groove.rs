// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
//! Gossamer Groove endpoint for panic-attacker.
//!
//! Exposes panic-attacker's static-analysis capabilities via the groove
//! discovery protocol. Any groove-aware system (Gossamer, PanLL, Hypatia,
//! etc.) can discover panic-attacker by probing GET /.well-known/groove
//! on port 7600.
//!
//! panic-attacker works standalone as a CLI tool. When groove consumers
//! connect, they gain access to the 47-language static analysis engine,
//! the miniKanren logic engine, and the 20-category weak point detection.
//!
//! The groove connector types are formally verified in Gossamer's Groove.idr:
//! - IsSubset proves consumers can only connect if panic-attacker satisfies
//!   their needs
//! - GrooveHandle is linear: consumers MUST disconnect (no dangling grooves)
//!
//! ## Groove Protocol
//!
//! - `GET  /.well-known/groove` — Capability manifest (JSON)
//! - `GET  /health`             — Simple health check
//!
//! ## Capabilities Offered
//!
//! - `static-analysis` — 47-language static analysis with 20 weak point categories
//!
//! ## Capabilities Consumed (enhanced when available)
//!
//! - `octad-storage` (from VeriSimDB) — Persist scan results as octad entities
//! - `workflow` (from CI/CD) — Trigger scans on push events

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

/// Maximum HTTP request size (16 KiB).
const MAX_REQUEST_SIZE: usize = 16 * 1024;

/// Build the groove manifest JSON for panic-attacker.
fn manifest(port: u16) -> String {
    format!(
        r#"{{
  "groove_version": "1",
  "service_id": "panic-attacker",
  "service_version": "{}",
  "capabilities": {{
    "static_analysis": {{
      "type": "static-analysis",
      "description": "Universal static analysis and logic-based bug signature detection for 47 languages",
      "protocol": "http",
      "endpoint": "/api/v1/scan",
      "requires_auth": false,
      "panel_compatible": true
    }}
  }},
  "consumes": ["octad-storage", "workflow"],
  "endpoints": {{
    "api": "http://localhost:{}/api/v1",
    "health": "http://localhost:{}/health"
  }},
  "health": "/health",
  "applicability": ["individual", "team"]
}}"#,
        env!("CARGO_PKG_VERSION"),
        port,
        port
    )
}

/// Run the groove discovery HTTP server on the given port.
///
/// This is a blocking synchronous server (no tokio dependency required).
/// panic-attacker is primarily a CLI tool without an async runtime, so we
/// use std::net for the groove endpoint. This keeps the dependency footprint
/// minimal and avoids pulling in tokio for a single discovery endpoint.
pub fn run(port: u16) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let listener = TcpListener::bind(addr)?;
    println!("[groove] panic-attacker groove endpoint listening on {}", addr);
    println!("[groove] Probe: curl http://localhost:{}/.well-known/groove", port);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(e) = handle_request(&mut stream, port) {
                    eprintln!("[groove] Request error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[groove] Accept error: {}", e);
            }
        }
    }

    Ok(())
}

/// Handle a single groove HTTP request.
fn handle_request(
    stream: &mut TcpStream,
    port: u16,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_SIZE];
    let n = stream.read(&mut buf)?;
    let request = std::str::from_utf8(&buf[..n])?;

    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_response(stream, 400, "text/plain", "Bad Request")?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    match (method, path) {
        // GET /.well-known/groove — Return the capability manifest.
        ("GET", "/.well-known/groove") => {
            let json = manifest(port);
            send_response(stream, 200, "application/json", &json)?;
        }

        // GET /health — Simple health check.
        ("GET", "/health") => {
            send_response(
                stream,
                200,
                "application/json",
                r#"{"status":"ok","service":"panic-attacker"}"#,
            )?;
        }

        // Unknown route.
        _ => {
            send_response(stream, 404, "text/plain", "Not Found")?;
        }
    }

    Ok(())
}

/// Send an HTTP response with the given content type and body.
fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> anyhow::Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Unknown",
    };
    let response = format!(
        "HTTP/1.0 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}
