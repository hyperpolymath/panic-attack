// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Attack profile loading for custom argument sets.

use crate::types::{AttackAxis, ProbeMode};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Upper bound on attack-profile config reads. Profiles are short curated
/// JSON/YAML documents; 4 MiB is far beyond realistic sizes and bounds
/// a tampered or malformed input.
const PROFILE_FILE_READ_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AttackProfile {
    #[serde(default)]
    pub common_args: Vec<String>,
    #[serde(default)]
    pub axes: HashMap<AttackAxis, Vec<String>>,
    #[serde(default)]
    pub probe_mode: Option<ProbeMode>,
}

impl AttackProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let content = {
            let mut buf = String::new();
            File::open(path)
                .with_context(|| format!("opening attack profile {}", path.display()))?
                .take(PROFILE_FILE_READ_LIMIT)
                .read_to_string(&mut buf)
                .with_context(|| format!("reading attack profile {}", path.display()))?;
            buf
        };
        // Extension-based dispatch is explicit to avoid ambiguous parsing behavior.
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => serde_json::from_str(&content)
                .with_context(|| format!("parsing json attack profile {}", path.display())),
            Some(ext) if crate::yaml::is_extension(ext) => crate::yaml::from_str(&content)
                .with_context(|| format!("parsing yaml attack profile {}", path.display())),
            _ => Err(anyhow!(
                "unsupported attack profile extension for {}",
                path.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn loads_kyaml_profile() {
        // Output of `yq -o kyaml` for a YAML attack profile.
        let dir = TempDir::new().expect("tempdir should create");
        let path = dir.path().join("profile.kyaml");
        std::fs::write(
            &path,
            "{\n  common_args: [\n    \"--config\",\n    \"cfg.toml\",\n  ],\n  axes: {\n    cpu: [\n      \"--iterations\",\n      \"5000\",\n    ],\n  },\n  probe_mode: \"always\",\n}\n",
        )
        .expect("profile should write");

        let profile = AttackProfile::load(&path).expect("kyaml profile should load");
        assert_eq!(profile.common_args, ["--config", "cfg.toml"]);
        assert_eq!(
            profile.axes.get(&AttackAxis::Cpu).map(Vec::as_slice),
            Some(["--iterations".to_string(), "5000".to_string()].as_slice())
        );
        assert_eq!(profile.probe_mode, Some(ProbeMode::Always));
    }
}
