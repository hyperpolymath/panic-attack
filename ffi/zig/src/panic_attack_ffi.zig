// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// panic-attack FFI — C-compatible bridge for static analysis operations.
// Mirrors PanicAttack.ABI.Types (Idris2).

const std = @import("std");

pub const Severity = enum(i32) {
    info = 0,
    warning = 1,
    @"error" = 2,
    critical = 3,
};

pub const ScanOp = enum(i32) {
    assail = 0,
    ambush = 1,
    abduct = 2,
    adjudicate = 3,
    axial = 4,
};

/// Compare two severity levels. Returns -1, 0, or 1.
pub export fn panic_severity_compare(a: i32, b: i32) callconv(.C) i32 {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

/// Check if a severity meets a minimum threshold.
pub export fn panic_severity_meets(severity: i32, threshold: i32) callconv(.C) i32 {
    return if (severity >= threshold) 1 else 0;
}

/// Validate language ID is in bounds (0-46).
pub export fn panic_valid_lang(lang_id: i32) callconv(.C) i32 {
    return if (lang_id >= 0 and lang_id < 47) 1 else 0;
}

test "severity ordering" {
    try std.testing.expectEqual(@as(i32, -1), panic_severity_compare(0, 3));
    try std.testing.expectEqual(@as(i32, 0), panic_severity_compare(2, 2));
    try std.testing.expectEqual(@as(i32, 1), panic_severity_compare(3, 0));
}

test "severity threshold" {
    try std.testing.expectEqual(@as(i32, 1), panic_severity_meets(3, 2));
    try std.testing.expectEqual(@as(i32, 0), panic_severity_meets(0, 2));
}

test "language bounds" {
    try std.testing.expectEqual(@as(i32, 1), panic_valid_lang(0));
    try std.testing.expectEqual(@as(i32, 1), panic_valid_lang(46));
    try std.testing.expectEqual(@as(i32, 0), panic_valid_lang(47));
    try std.testing.expectEqual(@as(i32, 0), panic_valid_lang(-1));
}
