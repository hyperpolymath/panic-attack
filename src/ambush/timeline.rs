// SPDX-License-Identifier: PMPL-1.0-or-later

//! Ambush timeline specification and parsing.

use crate::types::{AttackAxis, IntensityLevel};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TimelinePlan {
    pub program: Option<PathBuf>,
    pub duration: Duration,
    pub events: Vec<TimelineEventPlan>,
}

#[derive(Debug, Clone)]
pub struct TimelineEventPlan {
    pub id: String,
    pub axis: AttackAxis,
    pub start_offset: Duration,
    pub duration: Duration,
    pub intensity: IntensityLevel,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TimelineSpec {
    pub program: Option<PathBuf>,
    pub duration: Option<String>,
    pub tracks: Vec<TimelineTrackSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct TimelineTrackSpec {
    pub axis: String,
    pub events: Vec<TimelineEventSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct TimelineEventSpec {
    pub id: Option<String>,
    pub at: String,
    #[serde(rename = "for")]
    pub for_duration: String,
    pub intensity: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

pub fn load_timeline_with_default(
    path: &Path,
    default_intensity: Option<IntensityLevel>,
) -> Result<TimelinePlan> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading timeline {}", path.display()))?;
    let spec: TimelineSpec = if path.extension().and_then(|s| s.to_str()) == Some("yaml")
        || path.extension().and_then(|s| s.to_str()) == Some("yml")
    {
        serde_yaml::from_str(&content)
            .with_context(|| format!("parsing yaml timeline {}", path.display()))?
    } else {
        serde_json::from_str(&content)
            .with_context(|| format!("parsing json timeline {}", path.display()))?
    };

    build_plan(spec, default_intensity)
}

fn build_plan(
    spec: TimelineSpec,
    default_intensity: Option<IntensityLevel>,
) -> Result<TimelinePlan> {
    let mut events = Vec::new();
    for track in spec.tracks {
        let axis =
            parse_axis(&track.axis).ok_or_else(|| anyhow!("unknown axis '{}'", track.axis))?;
        for (index, event) in track.events.into_iter().enumerate() {
            let id = event
                .id
                .unwrap_or_else(|| format!("{}-{}", axis_label(axis), index + 1));
            let start_offset = parse_duration(&event.at)?;
            let duration = parse_duration(&event.for_duration)?;
            let intensity = match event.intensity {
                Some(raw) => {
                    parse_intensity(&raw).ok_or_else(|| anyhow!("unknown intensity '{}'", raw))?
                }
                None => default_intensity.unwrap_or(IntensityLevel::Medium),
            };
            events.push(TimelineEventPlan {
                id,
                axis,
                start_offset,
                duration,
                intensity,
                args: event.args,
            });
        }
    }

    let duration = match spec.duration {
        Some(raw) => parse_duration(&raw)?,
        None => infer_duration(&events)?,
    };

    Ok(TimelinePlan {
        program: spec.program,
        duration,
        events,
    })
}

fn infer_duration(events: &[TimelineEventPlan]) -> Result<Duration> {
    events
        .iter()
        .map(|event| event.start_offset + event.duration)
        .max()
        .ok_or_else(|| anyhow!("timeline has no events to infer duration"))
}

fn parse_axis(raw: &str) -> Option<AttackAxis> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "cpu" => Some(AttackAxis::Cpu),
        "memory" => Some(AttackAxis::Memory),
        "disk" => Some(AttackAxis::Disk),
        "network" => Some(AttackAxis::Network),
        "concurrency" => Some(AttackAxis::Concurrency),
        "time" => Some(AttackAxis::Time),
        _ => None,
    }
}

fn axis_label(axis: AttackAxis) -> &'static str {
    match axis {
        AttackAxis::Cpu => "cpu",
        AttackAxis::Memory => "memory",
        AttackAxis::Disk => "disk",
        AttackAxis::Network => "network",
        AttackAxis::Concurrency => "concurrency",
        AttackAxis::Time => "time",
    }
}

fn parse_intensity(raw: &str) -> Option<IntensityLevel> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "light" => Some(IntensityLevel::Light),
        "medium" => Some(IntensityLevel::Medium),
        "heavy" => Some(IntensityLevel::Heavy),
        "extreme" => Some(IntensityLevel::Extreme),
        _ => None,
    }
}

fn parse_duration(raw: &str) -> Result<Duration> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(anyhow!("duration cannot be empty"));
    }

    let (value_str, unit) = if trimmed.ends_with("ms") {
        (&trimmed[..trimmed.len() - 2], "ms")
    } else if trimmed.ends_with('s') {
        (&trimmed[..trimmed.len() - 1], "s")
    } else if trimmed.ends_with('m') {
        (&trimmed[..trimmed.len() - 1], "m")
    } else if trimmed.ends_with('h') {
        (&trimmed[..trimmed.len() - 1], "h")
    } else {
        (trimmed.as_str(), "s")
    };

    let value: f64 = value_str
        .parse()
        .with_context(|| format!("invalid duration '{}'", raw))?;
    if value.is_sign_negative() {
        return Err(anyhow!("duration cannot be negative: {}", raw));
    }

    let millis = match unit {
        "ms" => value,
        "s" => value * 1000.0,
        "m" => value * 60_000.0,
        "h" => value * 3_600_000.0,
        _ => value * 1000.0,
    };
    Ok(Duration::from_millis(millis.round() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_bare_number_defaults_to_seconds() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_empty_fails() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_parse_duration_negative_fails() {
        assert!(parse_duration("-5s").is_err());
    }

    #[test]
    fn test_parse_axis() {
        assert_eq!(parse_axis("cpu"), Some(AttackAxis::Cpu));
        assert_eq!(parse_axis("memory"), Some(AttackAxis::Memory));
        assert_eq!(parse_axis("disk"), Some(AttackAxis::Disk));
        assert_eq!(parse_axis("network"), Some(AttackAxis::Network));
        assert_eq!(parse_axis("concurrency"), Some(AttackAxis::Concurrency));
        assert_eq!(parse_axis("time"), Some(AttackAxis::Time));
        assert_eq!(parse_axis("CPU"), Some(AttackAxis::Cpu));
        assert_eq!(parse_axis("bogus"), None);
    }

    #[test]
    fn test_parse_intensity() {
        assert_eq!(parse_intensity("light"), Some(IntensityLevel::Light));
        assert_eq!(parse_intensity("medium"), Some(IntensityLevel::Medium));
        assert_eq!(parse_intensity("heavy"), Some(IntensityLevel::Heavy));
        assert_eq!(parse_intensity("extreme"), Some(IntensityLevel::Extreme));
        assert_eq!(parse_intensity("HEAVY"), Some(IntensityLevel::Heavy));
        assert_eq!(parse_intensity("invalid"), None);
    }

    #[test]
    fn test_load_timeline_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("timeline.json");
        std::fs::write(
            &path,
            r#"{
                "duration": "10s",
                "tracks": [
                    {
                        "axis": "cpu",
                        "events": [
                            {"at": "0s", "for": "5s", "intensity": "light"}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap();

        let plan = load_timeline_with_default(&path, None).unwrap();
        assert_eq!(plan.duration, Duration::from_secs(10));
        assert_eq!(plan.events.len(), 1);
        assert_eq!(plan.events[0].axis, AttackAxis::Cpu);
        assert_eq!(plan.events[0].intensity, IntensityLevel::Light);
    }

    #[test]
    fn test_load_timeline_yaml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("timeline.yaml");
        std::fs::write(
            &path,
            "duration: '15s'\ntracks:\n  - axis: memory\n    events:\n      - at: '2s'\n        for: '8s'\n        intensity: heavy\n",
        )
        .unwrap();

        let plan = load_timeline_with_default(&path, None).unwrap();
        assert_eq!(plan.duration, Duration::from_secs(15));
        assert_eq!(plan.events.len(), 1);
        assert_eq!(plan.events[0].axis, AttackAxis::Memory);
        assert_eq!(plan.events[0].intensity, IntensityLevel::Heavy);
    }

    #[test]
    fn test_timeline_infers_duration_from_events() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("timeline.json");
        std::fs::write(
            &path,
            r#"{
                "tracks": [
                    {
                        "axis": "cpu",
                        "events": [
                            {"at": "5s", "for": "10s"}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap();

        let plan = load_timeline_with_default(&path, Some(IntensityLevel::Medium)).unwrap();
        // 5s start + 10s duration = 15s total
        assert_eq!(plan.duration, Duration::from_secs(15));
    }

    #[test]
    fn test_timeline_multiple_tracks() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("timeline.json");
        std::fs::write(
            &path,
            r#"{
                "duration": "20s",
                "tracks": [
                    {
                        "axis": "cpu",
                        "events": [
                            {"id": "cpu-1", "at": "0s", "for": "5s"},
                            {"id": "cpu-2", "at": "5s", "for": "5s"}
                        ]
                    },
                    {
                        "axis": "memory",
                        "events": [
                            {"id": "mem-1", "at": "3s", "for": "10s", "intensity": "extreme"}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap();

        let plan = load_timeline_with_default(&path, Some(IntensityLevel::Medium)).unwrap();
        assert_eq!(plan.events.len(), 3);
        assert_eq!(plan.events[0].id, "cpu-1");
        assert_eq!(plan.events[1].id, "cpu-2");
        assert_eq!(plan.events[2].id, "mem-1");
        assert_eq!(plan.events[2].intensity, IntensityLevel::Extreme);
    }

    #[test]
    fn test_timeline_default_intensity() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("timeline.json");
        std::fs::write(
            &path,
            r#"{"duration": "5s", "tracks": [{"axis": "cpu", "events": [{"at": "0s", "for": "5s"}]}]}"#,
        )
        .unwrap();

        let plan = load_timeline_with_default(&path, Some(IntensityLevel::Heavy)).unwrap();
        assert_eq!(plan.events[0].intensity, IntensityLevel::Heavy);
    }

    #[test]
    fn test_timeline_auto_generated_ids() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("timeline.json");
        std::fs::write(
            &path,
            r#"{"duration": "5s", "tracks": [{"axis": "disk", "events": [{"at": "0s", "for": "2s"}, {"at": "2s", "for": "3s"}]}]}"#,
        )
        .unwrap();

        let plan = load_timeline_with_default(&path, None).unwrap();
        assert_eq!(plan.events[0].id, "disk-1");
        assert_eq!(plan.events[1].id, "disk-2");
    }
}
