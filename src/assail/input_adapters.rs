// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! One registry for non-source input discovery, execution and coverage depth.

use super::configuration;
use crate::types::WeakPoint;
use anyhow::Result;
use std::path::Path;

#[derive(Debug)]
pub(super) struct UnsupportedInput(pub String);

impl std::fmt::Display for UnsupportedInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for UnsupportedInput {}

pub(super) struct EmbeddedScript {
    pub content: String,
    pub language: crate::types::Language,
    /// Exact structural field, or the beginning of the source block. Parsers
    /// that do not retain source spans must not invent a physical line number.
    pub origin: String,
}

#[derive(Default)]
pub(super) struct Analysis {
    pub findings: Vec<WeakPoint>,
    pub scripts: Vec<EmbeddedScript>,
}

#[derive(Clone, Copy)]
pub(super) enum Adapter {
    Configuration(configuration::Format),
    Html,
    Css,
    Container,
    Just,
    Forth,
}

impl Adapter {
    pub(super) fn detect(path: &Path) -> Option<Self> {
        if let Some(format) = configuration::Format::detect(path) {
            return Some(Self::Configuration(format));
        }
        let name = path.file_name()?.to_str()?;
        if name == "Containerfile"
            || name == "Dockerfile"
            || name.starts_with("Containerfile.")
            || name.starts_with("Dockerfile.")
        {
            return Some(Self::Container);
        }
        if matches!(name, "Justfile" | "justfile") {
            return Some(Self::Just);
        }
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "html" | "htm" => Some(Self::Html),
            "css" => Some(Self::Css),
            "just" => Some(Self::Just),
            "fs" | "fth" | "forth" | "4th" => Some(Self::Forth),
            _ => None,
        }
    }

    pub(super) fn description(self) -> &'static str {
        match self {
            Self::Configuration(format) => format.description(),
            Self::Html => "tree-sitter-html 0.23.2; markup security checks, embedded CSS parser and JavaScript heuristics; no browser, template-expansion or dataflow proof",
            Self::Css => "tree-sitter-css 0.25.0; CSS function and URL security checks; no computed-style or browser execution proof",
            Self::Container => "Containerfile instruction, JSON-exec and image-reference checks plus extracted shell/Python/JavaScript heuristics; no image resolution or build execution",
            Self::Just => "Just recipe/declaration extraction and interpreter-specific shell/Python/JavaScript heuristics; no import, interpolation or task execution",
            Self::Forth => "Forth word-level hazard checks with comment/string masking; ambiguous .fs rejected; no stack, grammar or execution proof",
        }
    }

    pub(super) fn analyze(self, content: &str, file: &str) -> Result<Analysis> {
        match self {
            Self::Configuration(format) => format.analyze_input(content, file),
            Self::Html => super::templates::html(content, file),
            Self::Css => super::templates::css(content, file),
            Self::Container => super::build_inputs::container(content, file),
            Self::Just => super::build_inputs::just(content, file),
            Self::Forth => super::forth::analyze(content, file),
        }
    }
}
