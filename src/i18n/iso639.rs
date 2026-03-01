// SPDX-License-Identifier: PMPL-1.0-or-later

//! ISO 639-1 language code validation and metadata.
//!
//! Ported from the lol (1000Langs) project's `Iso639.res` module which
//! handles the full ISO 639-1/2/3 hierarchy. This Rust version covers
//! the ISO 639-1 two-letter codes used by panic-attack's `--lang` flag.
//!
//! Reference: <https://www.loc.gov/standards/iso639-2/php/code_list.php>

/// Validates whether a string is a known ISO 639-1 two-letter language code.
///
/// Only checks the subset of codes relevant to panic-attack's translation
/// catalogs and aspell integration. Returns `true` for codes that aspell
/// can use as dictionary identifiers.
///
/// # Examples
/// ```
/// assert!(panic_attack::i18n::is_valid_iso639_1("en"));
/// assert!(panic_attack::i18n::is_valid_iso639_1("ja"));
/// assert!(!panic_attack::i18n::is_valid_iso639_1("xx"));
/// ```
#[allow(dead_code)]
pub fn is_valid_iso639_1(code: &str) -> bool {
    matches!(
        code,
        "aa" | "ab" | "af" | "ak" | "am" | "an" | "ar" | "as" | "av" | "ay" | "az"
            | "ba" | "be" | "bg" | "bh" | "bi" | "bm" | "bn" | "bo" | "br" | "bs"
            | "ca" | "ce" | "ch" | "co" | "cr" | "cs" | "cu" | "cv" | "cy"
            | "da" | "de" | "dv" | "dz"
            | "ee" | "el" | "en" | "eo" | "es" | "et" | "eu"
            | "fa" | "ff" | "fi" | "fj" | "fo" | "fr" | "fy"
            | "ga" | "gd" | "gl" | "gn" | "gu" | "gv"
            | "ha" | "he" | "hi" | "ho" | "hr" | "ht" | "hu" | "hy" | "hz"
            | "ia" | "id" | "ie" | "ig" | "ii" | "ik" | "io" | "is" | "it" | "iu"
            | "ja" | "jv"
            | "ka" | "kg" | "ki" | "kj" | "kk" | "kl" | "km" | "kn" | "ko" | "kr" | "ks" | "ku" | "kv" | "kw" | "ky"
            | "la" | "lb" | "lg" | "li" | "ln" | "lo" | "lt" | "lu" | "lv"
            | "mg" | "mh" | "mi" | "mk" | "ml" | "mn" | "mr" | "ms" | "mt" | "my"
            | "na" | "nb" | "nd" | "ne" | "ng" | "nl" | "nn" | "no" | "nr" | "nv" | "ny"
            | "oc" | "oj" | "om" | "or" | "os"
            | "pa" | "pi" | "pl" | "ps" | "pt"
            | "qu"
            | "rm" | "rn" | "ro" | "ru" | "rw"
            | "sa" | "sc" | "sd" | "se" | "sg" | "si" | "sk" | "sl" | "sm" | "sn" | "so" | "sq" | "sr" | "ss" | "st" | "su" | "sv" | "sw"
            | "ta" | "te" | "tg" | "th" | "ti" | "tk" | "tl" | "tn" | "to" | "tr" | "ts" | "tt" | "tw" | "ty"
            | "ug" | "uk" | "ur" | "uz"
            | "ve" | "vi" | "vo"
            | "wa" | "wo"
            | "xh"
            | "yi" | "yo"
            | "za" | "zh" | "zu"
    )
}

/// Returns the English name of an ISO 639-1 code.
///
/// Returns `None` for unrecognised codes. Only includes the languages
/// that panic-attack has active translation catalogs for, plus a handful
/// of common codes for display purposes.
#[allow(dead_code)]
pub fn language_name(code: &str) -> Option<&'static str> {
    match code {
        "en" => Some("English"),
        "es" => Some("Spanish"),
        "fr" => Some("French"),
        "de" => Some("German"),
        "ja" => Some("Japanese"),
        "pt" => Some("Portuguese"),
        "zh" => Some("Chinese"),
        "ko" => Some("Korean"),
        "it" => Some("Italian"),
        "ru" => Some("Russian"),
        "ar" => Some("Arabic"),
        "hi" => Some("Hindi"),
        "nl" => Some("Dutch"),
        "sv" => Some("Swedish"),
        "pl" => Some("Polish"),
        "tr" => Some("Turkish"),
        "vi" => Some("Vietnamese"),
        "th" => Some("Thai"),
        "uk" => Some("Ukrainian"),
        "cs" => Some("Czech"),
        "el" => Some("Greek"),
        "he" => Some("Hebrew"),
        "da" => Some("Danish"),
        "fi" => Some("Finnish"),
        "no" | "nb" => Some("Norwegian"),
        "hu" => Some("Hungarian"),
        "ro" => Some("Romanian"),
        "id" => Some("Indonesian"),
        "ms" => Some("Malay"),
        _ => None,
    }
}

/// Returns the native name of an ISO 639-1 language code.
///
/// Used in language selection UIs where users should see their language
/// written in its own script.
#[allow(dead_code)]
pub fn native_name(code: &str) -> Option<&'static str> {
    match code {
        "en" => Some("English"),
        "es" => Some("Español"),
        "fr" => Some("Français"),
        "de" => Some("Deutsch"),
        "ja" => Some("日本語"),
        "pt" => Some("Português"),
        "zh" => Some("中文"),
        "ko" => Some("한국어"),
        "it" => Some("Italiano"),
        "ru" => Some("Русский"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_codes_accepted() {
        assert!(is_valid_iso639_1("en"));
        assert!(is_valid_iso639_1("ja"));
        assert!(is_valid_iso639_1("de"));
        assert!(is_valid_iso639_1("zh"));
    }

    #[test]
    fn invalid_codes_rejected() {
        assert!(!is_valid_iso639_1("xx"));
        assert!(!is_valid_iso639_1(""));
        assert!(!is_valid_iso639_1("eng"));
        assert!(!is_valid_iso639_1("EN"));
    }

    #[test]
    fn language_names_resolve() {
        assert_eq!(language_name("en"), Some("English"));
        assert_eq!(language_name("ja"), Some("Japanese"));
        assert_eq!(language_name("xx"), None);
    }

    #[test]
    fn native_names_resolve() {
        assert_eq!(native_name("ja"), Some("日本語"));
        assert_eq!(native_name("de"), Some("Deutsch"));
        assert_eq!(native_name("xx"), None);
    }
}
