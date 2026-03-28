// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// panic-attack V-lang API — Static analysis scanner client.
module panic_attack

pub enum Severity {
	info
	warning
	@error
	critical
}

pub enum ScanOp {
	assail
	ambush
	abduct
	adjudicate
	axial
}

pub struct Finding {
pub:
	file     string
	line     int
	severity Severity
	message  string
	rule_id  string
}

fn C.panic_severity_compare(a int, b int) int
fn C.panic_severity_meets(severity int, threshold int) int
fn C.panic_valid_lang(lang_id int) int

// severity_meets checks if a finding meets a minimum severity threshold.
pub fn severity_meets(severity Severity, threshold Severity) bool {
	return C.panic_severity_meets(int(severity), int(threshold)) == 1
}

// is_supported_lang checks if a language ID is supported (0-46).
pub fn is_supported_lang(lang_id int) bool {
	return C.panic_valid_lang(lang_id) == 1
}
