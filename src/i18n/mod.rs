// SPDX-License-Identifier: PMPL-1.0-or-later

//! Internationalisation module for panic-attack.
//!
//! Provides a data-driven translation system with ISO 639-1 language code
//! validation. Inspired by the lol (1000Langs) project's ISO 639 handling
//! at `/var/mnt/eclipse/repos/standards/lol/src/utils/Iso639.res`.
//!
//! ## Supported languages
//!
//! | Code | Language | Native name      |
//! |------|----------|------------------|
//! | en   | English  | English          |
//! | es   | Spanish  | Espanol          |
//! | fr   | French   | Francais         |
//! | de   | German   | Deutsch          |
//! | ja   | Japanese | 日本語            |
//! | pt   | Portuguese | Portugues      |
//! | zh   | Chinese  | 中文              |
//! | ko   | Korean   | 한국어            |
//! | it   | Italian  | Italiano         |
//! | ru   | Russian  | Русский          |
//!
//! ## Design
//!
//! Translation keys use dotted namespaces: `"axial.title"`, `"rec.crash"`,
//! `"report.target"`. Lookups fall back to English when a key is missing in
//! the requested language. If the key is missing in English too, the key
//! string itself is returned (fail-open, never panics).
//!
//! The catalog is embedded at compile time as static data — no file I/O,
//! no async, no allocator pressure during translation lookups.

mod catalog;
mod iso639;

#[allow(unused_imports)]
pub use catalog::{t, t_or_key, Lang};
#[allow(unused_imports)]
pub use iso639::{is_valid_iso639_1, language_name, native_name};
