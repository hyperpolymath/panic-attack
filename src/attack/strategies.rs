// SPDX-License-Identifier: PMPL-1.0-or-later

//! Attack strategies for different axes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackStrategy {
    CpuStress,
    MemoryExhaustion,
    DiskThrashing,
    NetworkFlood,
    ConcurrencyStorm,
    TimeBomb,
}

impl AttackStrategy {
    pub fn description(&self) -> &str {
        // Human-readable labels are used directly in CLI progress output.
        match self {
            AttackStrategy::CpuStress => "Stress test CPU with high computational load",
            AttackStrategy::MemoryExhaustion => "Exhaust available memory with large allocations",
            AttackStrategy::DiskThrashing => "Thrash disk I/O with many file operations",
            AttackStrategy::NetworkFlood => "Flood network connections",
            AttackStrategy::ConcurrencyStorm => "Create concurrency storm with many threads/tasks",
            AttackStrategy::TimeBomb => "Run for extended duration to find time-dependent bugs",
        }
    }

    /// All available strategies
    #[allow(dead_code)]
    pub fn all() -> &'static [AttackStrategy] {
        &[
            AttackStrategy::CpuStress,
            AttackStrategy::MemoryExhaustion,
            AttackStrategy::DiskThrashing,
            AttackStrategy::NetworkFlood,
            AttackStrategy::ConcurrencyStorm,
            AttackStrategy::TimeBomb,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_strategies_have_descriptions() {
        for strategy in AttackStrategy::all() {
            let desc = strategy.description();
            assert!(!desc.is_empty(), "{:?} should have a non-empty description", strategy);
        }
    }

    #[test]
    fn test_six_strategies() {
        assert_eq!(AttackStrategy::all().len(), 6, "should have exactly 6 attack strategies");
    }

    #[test]
    fn test_strategy_equality() {
        assert_eq!(AttackStrategy::CpuStress, AttackStrategy::CpuStress);
        assert_ne!(AttackStrategy::CpuStress, AttackStrategy::TimeBomb);
    }
}
