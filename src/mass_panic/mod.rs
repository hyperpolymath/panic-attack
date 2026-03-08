// SPDX-License-Identifier: PMPL-1.0-or-later

//! Mass-panic: datacenter-scale codebase imaging and temporal navigation.
//!
//! This module provides the Rust-side types and logic for mass-panic mode.
//! It extends assemblyline with three capabilities:
//!
//! 1. **Imaging**: fNIRS-inspired system health maps — spatial risk density
//!    across the scan surface (repos, dirs, files) with functional connectivity
//!    edges between related risk zones.
//!
//! 2. **Temporal**: Time-series snapshots stored in VeriSimDB, enabling
//!    forward/backward navigation through system state, diff between any
//!    two points, trend detection, and impact analysis.
//!
//! 3. **Chapel bridge**: Protocol types and launcher for Chapel distributed
//!    orchestration across multiple machines. The Chapel layer is optional —
//!    single-machine scanning uses rayon via the assemblyline module.

pub mod imaging;
pub mod temporal;
