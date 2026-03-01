# Contributing to panic-attack

Thank you for your interest in contributing to panic-attack! This document provides guidelines and information for contributors.

## Code of Conduct

This project follows the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to j.d.a.jewell@open.ac.uk.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Detailed description** of the problem
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment** (OS, Rust version, panic-attack version)
- **Logs or error messages** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the proposed feature
- **Explain why this enhancement would be useful** to most users
- **List any alternatives** you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding standards** described below
3. **Add tests** for any new functionality
4. **Update documentation** including README, rustdoc, and examples
5. **Ensure all tests pass** (`cargo test`)
6. **Ensure zero warnings** (`cargo build --release`)
7. **Run clippy** (`cargo clippy -- -D warnings`)
8. **Format code** (`cargo fmt`)
9. **Write a clear commit message** following the project's commit style

## Development Setup

### Prerequisites

- Rust 1.85.0 or later (MSRV)
- Cargo
- Git
- just (optional, for task automation)

### Building

```bash
git clone https://github.com/hyperpolymath/panic-attacker.git
cd panic-attacker
cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run readiness tests (machine-verifiable CRG grades)
just readiness

# Run readiness summary (pass/fail per grade)
just readiness-summary

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Running Locally

```bash
cargo run -- assail ./examples/vulnerable_program.rs --verbose
```

## Coding Standards

### Rust Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `cargo fmt` for consistent formatting
- Use `cargo clippy` to catch common mistakes
- Maximum line length: 100 characters (flexible for readability)

### Documentation

- All public APIs must have rustdoc comments
- Include examples in rustdoc where appropriate
- Keep comments up-to-date with code changes
- Use `//!` for module-level documentation
- Use `///` for item-level documentation

### Testing

- Write unit tests for all non-trivial functions
- Write integration tests for user-facing features
- Aim for 80% code coverage
- Test edge cases and error conditions
- Use descriptive test names: `test_<what>_<condition>_<expected_result>`
- Readiness tests use CRG grade prefixes: `readiness_d_`, `readiness_c_`, `readiness_b_`

### Commit Messages

Follow the Conventional Commits specification:

```
<type>: <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Example:
```
feat: add Latin-1 fallback for non-UTF-8 files

Implements encoding_rs fallback when UTF-8 decoding fails.
Verbose mode logs skipped files. Fixes handling of vendored
C files with non-ASCII author names.

Closes #42
```

## Project Structure

```
panic-attacker/
├── src/
│   ├── main.rs              # CLI entry point (clap) — 20 subcommands
│   ├── lib.rs               # Library API
│   ├── types.rs             # Core types (47 languages, 20 categories)
│   ├── assail/              # Static analysis engine
│   │   ├── analyzer.rs      # 47-language analyzer with per-file detection
│   │   └── patterns.rs      # Language-specific attack patterns
│   ├── kanren/              # miniKanren-inspired logic engine
│   │   ├── core.rs          # Unification, substitution, fact DB
│   │   ├── taint.rs         # Source-to-sink taint analysis
│   │   ├── crosslang.rs     # FFI boundary vulnerability chains
│   │   └── strategy.rs      # Risk-weighted search prioritisation
│   ├── attack/              # 6-axis stress testing
│   │   ├── executor.rs      # Attack execution engine
│   │   └── strategies.rs    # Per-axis attack strategies
│   ├── signatures/          # Logic-based bug signature detection
│   │   ├── engine.rs        # SignatureEngine (use-after-free, deadlock, etc.)
│   │   └── rules.rs         # Detection rules
│   ├── report/              # Report generation and output
│   │   ├── generator.rs     # AssaultReport builder
│   │   └── formatter.rs     # Output formatting (text, JSON, YAML, Nickel, SARIF)
│   ├── assemblyline.rs      # Batch scanning with rayon parallelism + BLAKE3
│   ├── notify.rs            # Notification pipeline (markdown + GitHub issues)
│   ├── attestation/         # Cryptographic attestation chain
│   │   ├── intent.rs        # Pre-execution commitment
│   │   ├── evidence.rs      # Rolling hash accumulator
│   │   ├── seal.rs          # Post-execution binding
│   │   ├── chain.rs         # Chain builder orchestration
│   │   └── envelope.rs      # A2ML envelope wrapper
│   ├── ambush/              # Ambient stressors + DAW-style timeline
│   ├── amuck/               # Mutation combinations
│   ├── abduct/              # Isolation + time-skew
│   ├── adjudicate/          # Campaign verdict aggregation
│   ├── axial/               # Reaction observation
│   ├── a2ml/                # AI manifest protocol
│   ├── panll/               # PanLL event-chain export
│   ├── storage/             # Filesystem + VerisimDB persistence
│   ├── i18n/                # Multi-language support (ISO 639-1, 10 languages)
│   └── diagnostics.rs       # Self-check (version, fleet, attestation, panicbot)
├── tests/                   # Integration + readiness tests
├── examples/                # Example programs
├── .machine_readable/       # SCM checkpoint files + bot directives
└── .github/workflows/       # CI/CD workflows
```

## RSR Compliance

This project follows RSR (Reproducible Software Repositories) standards:

### Critical Invariants

1. **SCM files in .machine_readable/ only** - Never put STATE.scm, ECOSYSTEM.scm, or META.scm in the repository root
2. **AI manifest required** - AI.a2ml must be present and up-to-date
3. **License consistency** - All files must use PMPL-1.0-or-later (SPDX header)
4. **Author attribution** - Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

### Updating Checkpoint Files

When making significant changes, update:
- `.machine_readable/STATE.scm` - Current state, completion %, next actions
- `.machine_readable/ECOSYSTEM.scm` - If adding new dependencies or integrations
- `.machine_readable/META.scm` - If making architectural decisions (ADRs)

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` with changes since last release
3. Update `.machine_readable/STATE.scm` with new version
4. Run full test suite: `cargo test`
5. Run readiness tests: `just readiness-summary`
6. Create git tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
7. Push tag: `git push origin vX.Y.Z`
8. GitHub Actions will create the release

## Getting Help

- **Documentation**: See README.md and DESIGN.md
- **Issues**: Check existing issues or create a new one
- **Email**: j.d.a.jewell@open.ac.uk
- **Roadmap**: See ROADMAP.md for future plans

## License

By contributing to panic-attack, you agree that your contributions will be licensed under the PMPL-1.0-or-later license. See the LICENSE file for details.

## Recognition

Contributors will be acknowledged in:
- CHANGELOG.md for their specific contributions
- GitHub contributors page
- Release notes

Thank you for contributing to panic-attack!
