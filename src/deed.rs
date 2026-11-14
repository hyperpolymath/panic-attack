// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Minimal reader for DEED documents (hyperpolymath standards,
//! `1-formats/deed/spec/abnf/deed.abnf` v2.0.0).
//!
//! A deed is an S-expression document: one or more `;; SPDX-…` header lines,
//! then a single form `(<doc-head> <field-or-clause>…)`. A field is
//! `:keyword value`; a clause is `(symbol <field-or-clause>…)`. The only
//! bracket is `(`, booleans are `#t`/`#f`, enums are symbols, and ids are
//! `#uuid"…"` or `#u8"domain:name"` literals.
//!
//! This reader implements the grammar as written, plus the side conditions a
//! consumer needs to refuse a file it cannot trust: the whole input is
//! consumed, `:schema-version` appears exactly once at the top level, no tab
//! appears anywhere, no line exceeds 998 octets, a comment ends in a line-end,
//! the filename dispatches to the doc-head it carries, and an identity field
//! never carries a `#u5` or a non-version-8 `#uuid`. It does not implement the
//! clause profiles (anchor, edict, descriptile …): a consumer checks the
//! profile it reads on top of the parsed tree.
//!
//! Every error carries the 1-based line it was found on. A malformed deed is
//! always an error, never a partial result.

use std::fmt;
use std::path::Path;

/// The doc-heads `deed.abnf` v2.0.0 admits.
pub const DOC_HEADS: &[&str] = &[
    "estate-deed",
    "repo-deed",
    "estate-atlas-deed",
    "praxis-deed",
    "contractile-deed",
    "descriptile-deed",
];

/// Identity fields (CHORA-SPEC 7.1): never a `#u5`, and a `#uuid` there is
/// version 8 (owner ruling Q2).
const IDENTITY_FIELDS: &[&str] = &[
    "repo-uuid",
    "estate-uuid",
    "forge-uuid",
    "beholding-chora",
    "of-chora",
    "uuid",
    "estate",
    "base",
    "forge",
    "repo",
];

/// Longest line `deed.abnf` allows, in octets, line-end excluded.
pub const MAX_LINE_OCTETS: usize = 998;

/// A parse or validation error, with the 1-based line it was found on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeedError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for DeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for DeedError {}

/// A deed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A string, escapes resolved.
    Str(String),
    Symbol(String),
    /// An integer, kept as written (leading zeros are not octal).
    Integer(String),
    Boolean(bool),
    /// `#u5"name"`: the body.
    Uuid5(String),
    /// `#u8"domain:name"`: the body (the profile C preimage).
    Uuid8(String),
    /// `#uuid"…"`: the lowercase RFC 9562 id.
    Uuid(String),
    Quoted(Box<Value>),
    List(Vec<Value>),
}

impl Value {
    /// A short name for the value's kind, for error messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Str(_) => "string",
            Value::Symbol(_) => "symbol",
            Value::Integer(_) => "integer",
            Value::Boolean(_) => "boolean",
            Value::Uuid5(_) => "#u5 literal",
            Value::Uuid8(_) => "#u8 literal",
            Value::Uuid(_) => "#uuid literal",
            Value::Quoted(_) => "quoted value",
            Value::List(_) => "list",
        }
    }
}

/// A member of a form or clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Field {
        key: String,
        value: Value,
        /// The v1.5.0 bang token after the value.
        bang: bool,
        line: usize,
    },
    Clause {
        name: String,
        items: Vec<Item>,
        line: usize,
    },
}

/// A parsed deed: its doc-head and its top-level members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deed {
    pub head: String,
    pub items: Vec<Item>,
}

/// The doc-head a deed file name dispatches to, or `None` when the name
/// matches no dispatch pattern (`deed.abnf` v2.0.0, exact names first).
pub fn head_for_filename(name: &str) -> Option<&'static str> {
    const VERBS: &[&str] = &["Intent", "Must", "Trust", "Adjust", "Dust", "Bust"];
    const DESCRIPTILES: &[&str] = &[
        "META",
        "STATE",
        "ECOSYSTEM",
        "AGENTIC",
        "NEUROSYM",
        "PLAYBOOK",
        "CLADE",
        "INTENT",
        "MUST",
        "TRUST",
        "ADJUST",
        "DUST",
        "BUST",
    ];
    let stem_ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    };
    if name == "estate_chora.deed" {
        return Some("estate-deed");
    }
    if name == "ATLAS.deed" {
        return Some("estate-atlas-deed");
    }
    if name == "0-AI-MANIFEST.deed" {
        return Some("repo-deed");
    }
    if VERBS.iter().any(|v| name == format!("{v}file.deed")) {
        return Some("contractile-deed");
    }
    if DESCRIPTILES.iter().any(|d| name == format!("{d}.deed")) {
        return Some("descriptile-deed");
    }
    if let Some(stem) = name.strip_suffix("_praxis.deed") {
        return stem_ok(stem).then_some("praxis-deed");
    }
    if let Some(stem) = name.strip_suffix("_chora.deed") {
        return stem_ok(stem).then_some("repo-deed");
    }
    None
}

/// Parse deed text. When `filename` is given, its base name must dispatch to
/// the doc-head the text carries.
pub fn parse(text: &str, filename: Option<&Path>) -> Result<Deed, DeedError> {
    check_lines(text)?;
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        line: 1,
    };
    p.header()?;
    p.opt_sep()?;
    let deed = p.form()?;
    p.opt_sep()?;
    if p.i < p.s.len() {
        return Err(p.err("content after the closing ')' of the form"));
    }
    if let Some(path) = filename {
        let base = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        match head_for_filename(base) {
            None => {
                return Err(DeedError {
                    line: 1,
                    message: format!("filename {base:?} matches no deed dispatch pattern"),
                })
            }
            Some(want) if want != deed.head => {
                return Err(DeedError {
                    line: 1,
                    message: format!(
                        "doc-head/filename mismatch: {base} dispatches to {want} but parses as {}",
                        deed.head
                    ),
                })
            }
            Some(_) => {}
        }
    }
    Ok(deed)
}

/// No tab anywhere, and no line longer than [`MAX_LINE_OCTETS`].
fn check_lines(text: &str) -> Result<(), DeedError> {
    for (k, raw) in text.split('\n').enumerate() {
        if raw.contains('\t') {
            return Err(DeedError {
                line: k + 1,
                message: "HTAB (tab) is an invalid separator anywhere in a deed".into(),
            });
        }
        let body = raw.strip_suffix('\r').unwrap_or(raw);
        if body.len() > MAX_LINE_OCTETS {
            return Err(DeedError {
                line: k + 1,
                message: format!(
                    "line is {} octets; a deed line is at most {MAX_LINE_OCTETS}",
                    body.len()
                ),
            });
        }
    }
    Ok(())
}

fn is_symbol_start(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

fn is_symbol_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"./*<>=!?+-_".contains(&b)
}

/// `text-char`: VCHAR, SP, or any byte of a multi-byte UTF-8 sequence (the
/// input is a `&str`, so the sequence is well formed).
fn is_text_byte(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b >= 0x80
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    line: usize,
}

impl Parser<'_> {
    fn err(&self, message: impl Into<String>) -> DeedError {
        DeedError {
            line: self.line,
            message: message.into(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn starts_with(&self, lit: &[u8]) -> bool {
        self.s[self.i..].starts_with(lit)
    }

    /// Consume a line-end (LF or CRLF), or fail.
    fn line_end(&mut self) -> Result<(), DeedError> {
        if self.starts_with(b"\r\n") {
            self.i += 2;
        } else if self.peek() == Some(b'\n') {
            self.i += 1;
        } else if self.i >= self.s.len() {
            return Err(self.err("a comment or header line must end in a line-end"));
        } else {
            return Err(self.err("control character where a line-end was expected"));
        }
        self.line += 1;
        Ok(())
    }

    /// `header = 1*spdx-line`, `spdx-line = ";;" SP "SPDX-" 1*text-char line-end`.
    fn header(&mut self) -> Result<(), DeedError> {
        let mut count = 0;
        while self.starts_with(b";; SPDX-") {
            self.i += b";; SPDX-".len();
            let start = self.i;
            while self.peek().is_some_and(is_text_byte) {
                self.i += 1;
            }
            if self.i == start {
                return Err(self.err("empty SPDX header line"));
            }
            self.line_end()?;
            count += 1;
        }
        if count == 0 {
            return Err(self.err(
                "deed must begin with at least one SPDX header line (';; SPDX-License-Identifier: …')",
            ));
        }
        Ok(())
    }

    /// `[token-sep]`; returns whether anything was consumed.
    fn opt_sep(&mut self) -> Result<bool, DeedError> {
        let start = self.i;
        loop {
            match self.peek() {
                Some(b' ') => self.i += 1,
                Some(b'\n') | Some(b'\r') => self.line_end()?,
                Some(b';') => {
                    self.i += 1;
                    while self.peek().is_some_and(is_text_byte) {
                        self.i += 1;
                    }
                    self.line_end()?;
                }
                _ => break,
            }
        }
        Ok(self.i > start)
    }

    fn symbol(&mut self) -> Result<String, DeedError> {
        if !self.peek().is_some_and(is_symbol_start) {
            return Err(
                self.err("expected a symbol (a letter, then letters, digits or ./*<>=!?+-_)")
            );
        }
        let start = self.i;
        while self.peek().is_some_and(is_symbol_char) {
            self.i += 1;
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    /// After a value, the next byte must begin a separator or close a form.
    fn delimited(&self) -> Result<(), DeedError> {
        match self.peek() {
            None | Some(b' ') | Some(b'\n') | Some(b'\r') | Some(b';') | Some(b')') => Ok(()),
            Some(b) => Err(self.err(format!(
                "unexpected {:?} directly after a value; a separator or ')' must follow",
                b as char
            ))),
        }
    }

    /// `form = "(" doc-head 1*(token-sep (field / clause)) [token-sep] ")"`.
    fn form(&mut self) -> Result<Deed, DeedError> {
        if self.peek() != Some(b'(') {
            return Err(self.err("expected '(' to open the deed form"));
        }
        self.i += 1;
        let head_line = self.line;
        let head = self.symbol()?;
        if !DOC_HEADS.contains(&head.as_str()) {
            return Err(DeedError {
                line: head_line,
                message: format!("unknown doc-head {head:?}"),
            });
        }
        let items = self.members(&head, 0, false)?;
        if items.is_empty() {
            return Err(self.err("a deed form carries at least one field or clause"));
        }
        let versions = items
            .iter()
            .filter(|it| matches!(it, Item::Field { key, .. } if key == "schema-version"))
            .collect::<Vec<_>>();
        match versions.as_slice() {
            [Item::Field {
                value: Value::Str(_),
                ..
            }] => {}
            [Item::Field { line, .. }] => {
                return Err(DeedError {
                    line: *line,
                    message: ":schema-version must be a string".into(),
                })
            }
            [] => return Err(self.err("missing :schema-version (required exactly once)")),
            _ => return Err(self.err(":schema-version appears more than once")),
        }
        Ok(Deed { head, items })
    }

    /// Members of a form or clause up to and including its closing ")".
    /// `in_top_rule` is true only for the members of a top-level `(rule …)`
    /// clause, the one place a bang may appear.
    fn members(
        &mut self,
        head: &str,
        depth: usize,
        in_top_rule: bool,
    ) -> Result<Vec<Item>, DeedError> {
        let mut items = Vec::new();
        loop {
            let had_sep = self.opt_sep()?;
            match self.peek() {
                Some(b')') => {
                    self.i += 1;
                    return Ok(items);
                }
                None => return Err(self.err("unexpected end of input: unclosed '('")),
                Some(_) if !had_sep => {
                    return Err(self.err("a separator is required before each field or clause"))
                }
                Some(b':') => items.push(self.field(head, in_top_rule)?),
                Some(b'(') => {
                    self.i += 1;
                    let line = self.line;
                    let name = self.symbol()?;
                    let inner = self.members(head, depth + 1, depth == 0 && name == "rule")?;
                    items.push(Item::Clause {
                        name,
                        items: inner,
                        line,
                    });
                    self.delimited()?;
                }
                Some(b) => {
                    return Err(self.err(format!(
                        "expected a :field, a (clause …) or ')', found {:?}",
                        b as char
                    )))
                }
            }
        }
    }

    /// `field = keyword token-sep value [token-sep bang]`.
    fn field(&mut self, head: &str, in_top_rule: bool) -> Result<Item, DeedError> {
        let line = self.line;
        self.i += 1; // ':'
        let key = self.symbol()?;
        if !self.opt_sep()? {
            return Err(self.err(format!(
                "a separator is required between :{key} and its value (there is no '=' form)"
            )));
        }
        let value = self.value()?;
        // "Never true, false, yes, no": they lex as symbols, so the ban is a
        // value-level rule (DEED-GRAMMAR-SPEC; deed_lint does the same).
        if matches!(&value, Value::Symbol(s) if ["true", "false", "yes", "no"].contains(&s.as_str()))
        {
            return Err(DeedError {
                line,
                message: format!("boolean meaning must use #t/#f, not the bare symbol in :{key}"),
            });
        }
        if IDENTITY_FIELDS.contains(&key.as_str()) {
            match &value {
                Value::Uuid5(_) => {
                    return Err(DeedError {
                        line,
                        message: format!(
                            "identity field :{key} carries a #u5 literal; write #uuid\"<v8 id>\" or #u8\"domain:name\""
                        ),
                    })
                }
                Value::Uuid(id) if id.as_bytes()[14] != b'8' => {
                    return Err(DeedError {
                        line,
                        message: format!("identity field :{key} carries a non-version-8 id"),
                    })
                }
                _ => {}
            }
        }
        // An optional bang: a lone "!" after a separator.
        let save = (self.i, self.line);
        let mut bang = false;
        if self.opt_sep()? && self.peek() == Some(b'!') {
            let next = self.s.get(self.i + 1).copied();
            if !next.is_some_and(is_symbol_char) {
                self.i += 1;
                self.delimited()?;
                bang = true;
            }
        }
        if !bang {
            (self.i, self.line) = save;
        }
        // The bang is legal only on the :id of a top-level (rule …) clause
        // of a contractile-deed (deed.abnf v1.5.0).
        if bang && !(head == "contractile-deed" && in_top_rule && key == "id") {
            return Err(DeedError {
                line,
                message: "the bang '!' is allowed only on the :id of a top-level (rule …) clause of a contractile-deed".into(),
            });
        }
        Ok(Item::Field {
            key,
            value,
            bang,
            line,
        })
    }

    fn value(&mut self) -> Result<Value, DeedError> {
        let v = match self.peek() {
            Some(b'"') => Value::Str(self.string()?),
            Some(b'#') => self.hash_form()?,
            Some(b'\'') => {
                self.i += 1;
                match self.peek() {
                    Some(b'(') => Value::Quoted(Box::new(self.list()?)),
                    Some(b) if is_symbol_start(b) => {
                        Value::Quoted(Box::new(Value::Symbol(self.symbol()?)))
                    }
                    _ => return Err(self.err(
                        "only a symbol or a list may be quoted, with nothing between \"'\" and it",
                    )),
                }
            }
            Some(b'(') => self.list()?,
            Some(b'-') | Some(b'0'..=b'9') => {
                let start = self.i;
                if self.peek() == Some(b'-') {
                    self.i += 1;
                }
                let digits = self.i;
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.i += 1;
                }
                if self.i == digits {
                    return Err(self.err("'-' must be followed by digits"));
                }
                Value::Integer(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
            }
            Some(b) if is_symbol_start(b) => Value::Symbol(self.symbol()?),
            Some(b) => return Err(self.err(format!("expected a value, found {:?}", b as char))),
            None => return Err(self.err("unexpected end of input: expected a value")),
        };
        self.delimited()?;
        Ok(v)
    }

    /// `list = "(" [token-sep] [value *(token-sep value)] [token-sep] ")"`.
    fn list(&mut self) -> Result<Value, DeedError> {
        self.i += 1; // '('
        let mut out = Vec::new();
        loop {
            let had_sep = self.opt_sep()?;
            match self.peek() {
                Some(b')') => {
                    self.i += 1;
                    return Ok(Value::List(out));
                }
                None => return Err(self.err("unexpected end of input: unclosed list")),
                Some(_) if !out.is_empty() && !had_sep => {
                    return Err(self.err("list values must be separated"))
                }
                Some(b':') => {
                    return Err(
                        self.err("a list holds values only; a :keyword cannot appear in one")
                    )
                }
                Some(_) => out.push(self.value()?),
            }
        }
    }

    /// A string with exactly four escapes: `\"`, `\\`, `\n`, `\t`.
    fn string(&mut self) -> Result<String, DeedError> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                Some(b'\\') => {
                    let esc =
                        match self.s.get(self.i + 1) {
                            Some(b'"') => b'"',
                            Some(b'\\') => b'\\',
                            Some(b'n') => b'\n',
                            Some(b't') => b'\t',
                            _ => return Err(self.err(
                                "invalid escape; a deed string has exactly \\\" \\\\ \\n and \\t",
                            )),
                        };
                    out.push(esc);
                    self.i += 2;
                }
                Some(b) if is_text_byte(b) => {
                    out.push(b);
                    self.i += 1;
                }
                Some(_) => {
                    return Err(
                        self.err("control character or raw line break inside a string (use \\n)")
                    )
                }
            }
        }
    }

    fn hash_form(&mut self) -> Result<Value, DeedError> {
        if self.starts_with(b"#uuid") {
            self.i += 5;
            if self.peek() != Some(b'"') {
                return Err(self.err("#uuid must be followed immediately by a string"));
            }
            let id = self.string()?;
            if !valid_uuid_hex(&id) {
                return Err(self.err(format!(
                    "#uuid\"{id}\" is not a lowercase RFC 9562 id of version 5 or 8 and variant 10"
                )));
            }
            return Ok(Value::Uuid(id));
        }
        if self.starts_with(b"#u5") || self.starts_with(b"#u8") {
            let eight = self.s[self.i + 2] == b'8';
            self.i += 3;
            if self.peek() != Some(b'"') {
                return Err(self.err("#u5/#u8 must be followed immediately by a string"));
            }
            let body = self.string()?;
            if eight {
                let domain = body.split(':').next().unwrap_or_default();
                if !body.contains(':')
                    || domain.is_empty()
                    || !domain.bytes().all(|b| (0x21..=0x7e).contains(&b))
                {
                    return Err(self.err(format!(
                        "#u8\"{body}\" must be domain:name with a non-empty printable-ASCII domain"
                    )));
                }
                return Ok(Value::Uuid8(body));
            }
            return Ok(Value::Uuid5(body));
        }
        if self.starts_with(b"#t") || self.starts_with(b"#f") {
            let b = self.s[self.i + 1] == b't';
            self.i += 2;
            return Ok(Value::Boolean(b));
        }
        Err(self.err("unknown #-form; expected #t, #f, #uuid\"…\", #u8\"…\" or #u5\"…\""))
    }
}

/// `uuid-hex`: 8-4-4-4-12 lowercase hex, version 5 or 8, variant 10.
fn valid_uuid_hex(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (k, &c) in b.iter().enumerate() {
        let ok = match k {
            8 | 13 | 18 | 23 => c == b'-',
            14 => c == b'5' || c == b'8',
            19 => matches!(c, b'8' | b'9' | b'a' | b'b'),
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        };
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = ";; SPDX-License-Identifier: MPL-2.0\n";

    fn ok(body: &str) -> Deed {
        parse(&format!("{H}{body}"), None).unwrap_or_else(|e| panic!("{body}: {e}"))
    }

    fn bad(body: &str) -> DeedError {
        match parse(&format!("{H}{body}"), None) {
            Ok(d) => panic!("{body} parsed as {d:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn parses_fields_clauses_and_values() {
        let d = ok("(praxis-deed\n  :schema-version \"1.0.0\" ; c\n  :n -007 :b #t :q 'sym :l (1 \"a\" (x))\n  :id #uuid\"0889b37b-defb-831f-973c-e119500db00e\"\n  :c #u8\"gv-clade-index:github.com/o/x\"\n  (rule :x Type.Software.Lib))\n");
        assert_eq!(d.head, "praxis-deed");
        assert_eq!(d.items.len(), 8);
        assert!(
            matches!(&d.items[7], Item::Clause { name, items, line: 7 } if name == "rule" && items.len() == 1)
        );
    }

    #[test]
    fn string_escapes() {
        let d = ok("(praxis-deed :schema-version \"1\" :s \"a\\\"b\\\\c\\nd\\te §\")\n");
        assert!(
            matches!(&d.items[1], Item::Field { value: Value::Str(s), .. } if s == "a\"b\\c\nd\te §")
        );
    }

    #[test]
    fn refuses_what_the_grammar_refuses() {
        for body in [
            "(praxis-deed :schema-version = \"1\")",
            "(praxis-deed :canonical-name \"x\")",
            "(praxis-deed :schema-version \"1\" :schema-version \"2\")",
            "(praxis-deed :schema-version 1)",
            "(not-a-head :schema-version \"1\")",
            "(praxis-deed :schema-version \"1\"",
            "(praxis-deed :schema-version \"1\") x",
            "(praxis-deed :schema-version \"1\")(x)",
            "(praxis-deed :schema-version \"1\" :b #T)",
            "(praxis-deed :schema-version \"1\" :s \"a\\rb\")",
            "(praxis-deed :schema-version \"1\" :s \"a\nb\")",
            "(praxis-deed :schema-version \"1\" :q ' sym)",
            "(praxis-deed :schema-version \"1\" :q '1)",
            "(praxis-deed :schema-version \"1\" :x \"a\"\"b\")",
            "(praxis-deed :schema-version \"1\"(c :x 1))",
            "(praxis-deed :schema-version \"1\" :id \"x\" !)",
            "(contractile-deed :schema-version \"1\" (edict :id \"x\" !))",
            "(contractile-deed :schema-version \"1\" (rule (rule :id \"x\" !)))",
            "(praxis-deed :schema-version \"1\" :b true)",
            "(praxis-deed :schema-version \"1\" (c :b no))",
            "(praxis-deed :schema-version \"1\" :u #uuid\"0889B37B-defb-831f-973c-e119500db00e\")",
            "(praxis-deed :schema-version \"1\" :u #uuid\"0889b37b-defb-431f-973c-e119500db00e\")",
            "(praxis-deed :schema-version \"1\" :u #u8\"nodomain\")",
            "(praxis-deed :schema-version \"1\" :beholding-chora #u5\"x\")",
            "(praxis-deed :schema-version \"1\" :repo-uuid #uuid\"0889b37b-defb-531f-973c-e119500db00e\")",
            "(praxis-deed :schema-version \"1\" :l (:k 1))",
            "(praxis-deed :schema-version \"1\") ; no line-end after this comment",
        ] {
            bad(body);
        }
    }

    #[test]
    fn refuses_a_missing_header_tabs_and_long_lines() {
        assert!(parse("(praxis-deed :schema-version \"1\")\n", None).is_err());
        assert!(parse(&format!("{H}(praxis-deed\t:schema-version \"1\")\n"), None).is_err());
        let long = format!(
            "{H}(praxis-deed :schema-version \"1\" :s \"{}\")\n",
            "a".repeat(1000)
        );
        assert_eq!(parse(&long, None).unwrap_err().line, 2);
    }

    #[test]
    fn bang_on_a_top_level_rule_id() {
        let d = ok("(contractile-deed :schema-version \"1\" (rule :id \"r\" ! :x 1))\n");
        assert!(matches!(&d.items[1], Item::Clause { items, .. }
            if matches!(&items[0], Item::Field { bang: true, .. })));
    }

    #[test]
    fn error_lines_are_reported() {
        let e = bad("(praxis-deed\n  :schema-version \"1\"\n  :x #q)\n");
        assert_eq!(e.line, 4);
    }

    #[test]
    fn filename_dispatch() {
        let text = format!("{H}(praxis-deed :schema-version \"1\")\n");
        assert!(parse(&text, Some(Path::new("a/x_praxis.deed"))).is_ok());
        assert!(parse(&text, Some(Path::new("a/x_chora.deed"))).is_err());
        assert!(parse(&text, Some(Path::new("a/x.deed"))).is_err());
        assert_eq!(head_for_filename("estate_chora.deed"), Some("estate-deed"));
        assert_eq!(head_for_filename("Mustfile.deed"), Some("contractile-deed"));
        assert_eq!(head_for_filename("MUST.deed"), Some("descriptile-deed"));
        assert_eq!(head_for_filename("ANCHOR.deed"), None);
        assert_eq!(head_for_filename("_praxis.deed"), None);
    }
}
