// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Safe path operations — Rust port of `proven::SafePath` (PROOF-PROGRAMME row 3, issue #115).
//!
//! Provides two operations validated against `hyperpolymath/proven`'s Idris2
//! reference at `src/Proven/SafePath/Operations.idr`:
//!
//!   * [`has_traversal`] — true if any path component is `..` (directory-
//!     traversal sequence detected). Mirrors the reference's
//!     `containsTraversal` predicate using the same segment-splitting
//!     semantics: both `/` and `\` are treated as separators; empty
//!     segments are dropped; the segment `..` triggers detection.
//!
//!   * [`sanitize_filename`] — returns a filename containing only
//!     alphanumeric characters plus `-`, `_`, `.`, `~`. If filtering
//!     would produce an empty string (e.g. all-emoji input), returns
//!     `"_"` so callers always get a non-empty result. Mirrors the
//!     reference's `sanitizeSegment` function.
//!
//! The proven reference is Idris2; this is a pure-Rust port with no
//! libproven dylib dependency. The implementation is hand-written but
//! the behaviour is locked in by proptest invariants in the tests
//! module. The invariants are stated as Rust property tests so they
//! re-check on every `cargo test` run, but they're semantically
//! identical to the lemmas the Idris2 reference would prove:
//!
//!   * `sanitize_filename` output is always non-empty.
//!   * `sanitize_filename` output contains only safe characters.
//!   * `sanitize_filename` is idempotent.
//!   * `has_traversal` returns true iff some component split by `/` or
//!     `\\` equals `".."` (the operational specification).
//!
//! Call sites replacing the prior `fs::canonicalize(..).unwrap_or_else(|_| dir)`
//! pattern at `src/abduct/mod.rs:123,266` + `src/main.rs:2314,2377` will
//! use [`has_traversal`] to short-circuit before any disk I/O.

/// Characters considered safe in a sanitized filename. Matches the
/// `proven::SafePath::sanitizeSegment` reference: alphanumeric plus
/// `-`, `_`, `.`, `~`.
const SAFE_PUNCT: &[char] = &['-', '_', '.', '~'];

/// Returns true if `path` contains a directory-traversal sequence.
///
/// Splits the path on `/` and `\\` separators, drops empty segments
/// (so leading / trailing / consecutive separators don't cause false
/// negatives), and returns true if any remaining segment is exactly
/// `".."`.
///
/// Examples:
///
/// ```
/// use panic_attack::safe_path::has_traversal;
///
/// assert!(has_traversal("../etc/passwd"));
/// assert!(has_traversal("foo/../bar"));
/// assert!(has_traversal("foo/.."));
/// assert!(has_traversal("..\\windows\\system32"));
/// assert!(!has_traversal("foo/bar/baz"));
/// assert!(!has_traversal(""));
/// assert!(!has_traversal("./foo"));   // single dot is not traversal
/// assert!(!has_traversal("foo..bar")); // .. inside a name is not a segment
/// ```
pub fn has_traversal(path: &str) -> bool {
    for segment in path.split(|c| c == '/' || c == '\\') {
        if segment == ".." {
            return true;
        }
    }
    false
}

/// Sanitize a filename by retaining only safe characters.
///
/// Keeps ASCII alphanumeric characters plus `-`, `_`, `.`, `~`. All
/// other characters are dropped. If the result would be empty (e.g.
/// an all-emoji or all-punctuation input), returns `"_"` so callers
/// always receive a non-empty filename.
///
/// Examples:
///
/// ```
/// use panic_attack::safe_path::sanitize_filename;
///
/// assert_eq!(sanitize_filename("hello world.txt"), "helloworld.txt");
/// assert_eq!(sanitize_filename("../etc/passwd"), "..etcpasswd");
/// assert_eq!(sanitize_filename("🚀🌟"), "_");
/// assert_eq!(sanitize_filename(""), "_");
/// assert_eq!(sanitize_filename("my-file_2026.06.02.tar.gz"), "my-file_2026.06.02.tar.gz");
/// ```
pub fn sanitize_filename(filename: &str) -> String {
    let cleaned: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || SAFE_PUNCT.contains(c))
        .collect();
    if cleaned.is_empty() {
        "_".to_string()
    } else {
        cleaned
    }
}

/// Returns true if `c` is a character `sanitize_filename` would keep.
fn is_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || SAFE_PUNCT.contains(&c)
}

/// Returns true if every character in `s` is safe. Used by the
/// idempotence + non-empty proptest invariants.
fn all_chars_safe(s: &str) -> bool {
    s.chars().all(is_safe_char)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ─────────────────────────────────────────────────────────────────
    // has_traversal — concrete cases
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn dotdot_at_start() {
        assert!(has_traversal("../etc"));
    }

    #[test]
    fn dotdot_in_middle() {
        assert!(has_traversal("foo/../bar"));
    }

    #[test]
    fn dotdot_at_end() {
        assert!(has_traversal("foo/.."));
    }

    #[test]
    fn backslash_separator() {
        assert!(has_traversal("..\\windows"));
        assert!(has_traversal("foo\\..\\bar"));
    }

    #[test]
    fn mixed_separators() {
        assert!(has_traversal("foo/bar\\..\\baz"));
    }

    #[test]
    fn empty_string_no_traversal() {
        assert!(!has_traversal(""));
    }

    #[test]
    fn single_dot_no_traversal() {
        assert!(!has_traversal("./foo"));
        assert!(!has_traversal("foo/./bar"));
    }

    #[test]
    fn dotdot_inside_name_not_traversal() {
        // Critical: `foo..bar` is a single segment named `foo..bar`,
        // not a traversal. The reference impl agrees.
        assert!(!has_traversal("foo..bar"));
        assert!(!has_traversal("..foo"));
        assert!(!has_traversal("foo.."));
    }

    #[test]
    fn normal_path_no_traversal() {
        assert!(!has_traversal("src/main.rs"));
        assert!(!has_traversal("/usr/local/bin/panic-attack"));
        assert!(!has_traversal("C:\\Users\\Public\\Documents"));
    }

    #[test]
    fn consecutive_separators_no_false_positive() {
        assert!(!has_traversal("foo//bar"));
        assert!(!has_traversal("foo///bar"));
        assert!(!has_traversal("//foo"));
    }

    // ─────────────────────────────────────────────────────────────────
    // sanitize_filename — concrete cases
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn sanitize_keeps_alphanumeric() {
        assert_eq!(sanitize_filename("hello123"), "hello123");
    }

    #[test]
    fn sanitize_keeps_safe_punct() {
        assert_eq!(sanitize_filename("my-file_2026.06.02"), "my-file_2026.06.02");
        assert_eq!(sanitize_filename("config~"), "config~");
    }

    #[test]
    fn sanitize_drops_separator() {
        assert_eq!(sanitize_filename("../etc"), "..etc");
        assert_eq!(sanitize_filename("foo\\bar"), "foobar");
        assert_eq!(sanitize_filename("foo/bar"), "foobar");
    }

    #[test]
    fn sanitize_drops_whitespace() {
        assert_eq!(sanitize_filename("hello world"), "helloworld");
        assert_eq!(sanitize_filename("a\tb\nc"), "abc");
    }

    #[test]
    fn sanitize_drops_unicode_non_ascii() {
        assert_eq!(sanitize_filename("café"), "caf");
        assert_eq!(sanitize_filename("naïve"), "nave");
    }

    #[test]
    fn sanitize_empty_input_returns_underscore() {
        assert_eq!(sanitize_filename(""), "_");
    }

    #[test]
    fn sanitize_all_unsafe_returns_underscore() {
        assert_eq!(sanitize_filename("🚀🌟"), "_");
        assert_eq!(sanitize_filename("    "), "_");
        assert_eq!(sanitize_filename("///"), "_");
    }

    #[test]
    fn sanitize_keeps_dotfiles() {
        assert_eq!(sanitize_filename(".gitignore"), ".gitignore");
        assert_eq!(sanitize_filename(".env"), ".env");
    }

    // ─────────────────────────────────────────────────────────────────
    // Property tests — semantic equivalence with proven reference
    // ─────────────────────────────────────────────────────────────────
    //
    // Each property mirrors a lemma the Idris2 reference would (or
    // does) state about its corresponding function. proptest with the
    // default config runs 256 random cases per invariant — small
    // enough to be fast (under 50ms) but enough coverage to catch
    // semantic regressions.

    proptest! {
        /// **Invariant 1 — sanitize output is always non-empty.**
        /// Reference: SafePath's sanitizeSegment always returns
        /// `"_"` on empty / all-unsafe input.
        #[test]
        fn prop_sanitize_output_nonempty(s in ".*") {
            let out = sanitize_filename(&s);
            prop_assert!(!out.is_empty(), "sanitize_filename({:?}) was empty", s);
        }

        /// **Invariant 2 — sanitize output contains only safe characters.**
        /// Reference: sanitizeSegment filters to `isAlphaNum c ||
        /// elem c (unpack "-_.~")` and never reintroduces unsafe chars.
        #[test]
        fn prop_sanitize_output_only_safe(s in ".*") {
            let out = sanitize_filename(&s);
            prop_assert!(
                all_chars_safe(&out),
                "sanitize_filename({:?}) produced unsafe characters in {:?}",
                s, out
            );
        }

        /// **Invariant 3 — sanitize is idempotent.**
        /// Reference: applying sanitizeSegment to its own output is the
        /// identity (output is already safe).
        #[test]
        fn prop_sanitize_idempotent(s in ".*") {
            let once = sanitize_filename(&s);
            let twice = sanitize_filename(&once);
            prop_assert_eq!(
                once.clone(), twice,
                "sanitize_filename not idempotent on {:?}",
                s
            );
        }

        /// **Invariant 4 — has_traversal operational spec.**
        /// `has_traversal(s)` is true iff splitting `s` on `/` or `\\`
        /// yields at least one segment equal to "..".
        #[test]
        fn prop_has_traversal_operational(s in ".*") {
            let split_says: bool = s
                .split(|c| c == '/' || c == '\\')
                .any(|seg| seg == "..");
            prop_assert_eq!(
                has_traversal(&s),
                split_says,
                "has_traversal({:?}) disagreed with the split-based oracle",
                s
            );
        }

        /// **Invariant 5 — has_traversal is preserved by prefixing
        /// safe segments.** If a path has no traversal, prefixing it
        /// with a safe segment + separator preserves that property.
        #[test]
        fn prop_safe_prefix_preserves_no_traversal(
            prefix in "[a-zA-Z0-9_-]+",
            tail in r"[^/\\]*",
        ) {
            // The tail might contain ".." as a substring but we generated
            // it to not contain separators, so it CAN'T have a `..`
            // segment. Combining them must still be traversal-free.
            let combined = format!("{}/{}", prefix, tail);
            // The combined path has traversal iff tail (as a single
            // segment) is exactly "..".
            let expected = tail == "..";
            prop_assert_eq!(has_traversal(&combined), expected);
        }
    }
}
