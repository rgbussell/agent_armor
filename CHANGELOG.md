# Changelog

All notable changes to Agent Armor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Security hook implementation (`agent-armor-security.py`) with comprehensive pattern matching
- Tilde (`~`) expansion support for home directory paths in all path patterns
- Protection for shell configuration files in `noDeletePaths`:
  - `~/.bashrc`
  - `~/.zshrc`
  - `~/.profile`
  - `~/.bash_profile`
  - `~/.zsh_history`
  - `~/.bash_history`
- Comprehensive test suite (`tests/test_tilde_expansion.py`) covering:
  - Tilde expansion functionality
  - Bash command pattern blocking
  - Zero-access path enforcement
  - Read-only path enforcement
  - Safe operation validation

### Implementation Details
- **Hook Type**: PreToolUse hook for Bash, Read, Write, and Edit tools
- **Configuration**: Loads patterns from `.claude/skills/agent-armor/patterns.yaml`
- **Path Matching**: `PathMatcher` class with glob pattern support and tilde expansion
- **Security Features**:
  - Blocks 370+ dangerous command patterns
  - Enforces zero-access paths (credentials, keys, secrets)
  - Enforces read-only paths (lock files, system directories, build artifacts)
  - Protects critical files from deletion
  - Supports "ask" patterns for user confirmation (currently blocks with message)

### Technical Notes
- Tilde (`~`) in patterns is automatically expanded to user's home directory
- Supports glob patterns: `*.ext`, `**/*.ext`, directory patterns ending with `/`
- Exit code 2 blocks tool execution and provides error feedback to Claude
- 5-second timeout per hook execution
- Python 3 with PyYAML dependency required

### Fixed
- Tilde (`~`) patterns now properly expand to actual home directory path
- Shell configuration files now protected from accidental deletion
