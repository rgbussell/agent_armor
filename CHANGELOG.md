# Changelog

All notable changes to Agent Armor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security - Audit Report Protection
- **Security Audit Reports Excluded from Version Control**:
  - Added `SECURITY_AUDIT*.md` patterns to `.gitignore`
  - Removed `SECURITY_AUDIT_REPORT.md` from git tracking
  - Updated security evaluator skill to prevent audit reports in repository
  - Prevents exposure of detailed vulnerability information in public repositories
  - Security audit reports remain available locally for reference but won't be committed

### Fixed - Critical Security Vulnerabilities
- **CRITICAL-001: LLM Prompt Injection** - Fixed in Bash tool LLM validation hook:
  - Added COMMAND_START/COMMAND_END delimiters to isolate untrusted user input
  - Added explicit instructions for LLM to treat command as data, not instructions
  - Added strict JSON schema enforcement in prompt template
  - Prevents attackers from injecting instructions to bypass security validation
  - Location: `.claude/settings.json` Bash tool prompt hook
- **CRITICAL-002: Regular Expression Denial of Service (ReDoS)** - Fixed all 21 vulnerable regex patterns:
  - Fixed 4 nested quantifier patterns (rm, git clean, git push -f, git branch -D)
  - Fixed highest-risk pattern with multiple greedy quantifiers (docker rm -f)
  - Fixed 16 greedy dot-star patterns across AWS, GCP, Docker, Kubernetes, MongoDB, etc.
  - Replaced `.*` with `.*?` (non-greedy) or `[^\s]*` (negated character class)
  - Added MAX_COMMAND_LENGTH (100KB) limit to prevent ReDoS attacks
  - **Additional fixes from re-audit (2026-01-06):**
    - Line 29: Fixed chmod 777 nested quantifier `(-[^\s]+\s+)*` → `(-[^\s]+\s+){0,10}` (bounded repetition)
    - Line 240: Fixed docker rm pattern `[^\$]*-f[^\$]*` → `.*?-f.*?` (non-greedy, eliminates O(n²) complexity)
  - Prevents catastrophic backtracking and timeout-based security bypasses
  - All 32 existing tests passing after fixes

### Added - Modular Hook Architecture (Damage Control Integration)
- **Tool-Specific Hooks**: Migrated from single unified hook to three specialized hooks:
  - `bash-tool-agent-armor.py`: Validates bash commands against 370+ patterns, checks delete operations
  - `edit-tool-agent-armor.py`: Validates Edit/Read operations, enforces zero-access and read-only paths
  - `write-tool-agent-armor.py`: Validates Write operations, enforces zero-access and read-only paths
- **LLM-Based Security Validation**: Added AI prompt hook for Bash commands (defense-in-depth):
  - 10-second timeout for LLM analysis
  - Catches novel attack patterns not in regex database
  - Provides context-aware security review
- **Case-Insensitive Security Matching**: Zero-access paths now use case-insensitive matching:
  - Catches `.ENV`, `.Env`, `.env` variants
  - Protects `~/.SSH/`, `~/.ssh/` equally
  - Blocks `cert.PEM`, `cert.pem`, etc.
- **Read Tool Support**: Read operations now validated against zero-access paths
- **Multi-Path Configuration Fallback**: patterns.yaml loaded with priority:
  1. `.claude/hooks/agent-armor/patterns.yaml` (new location)
  2. `.claude/skills/agent-armor/patterns.yaml` (backward compat)
  3. Script directory (installed location)
- **Permissions System**: Added deny/ask lists in settings.json for fine-grained control
- **PEP 723 Metadata**: All hooks declare dependencies (`pyyaml>=6.0`, `python>=3.8`)
- **Enhanced Test Coverage**: Updated test suite with 32 passing tests including:
  - Case-insensitive security matching tests
  - Tool-specific hook validation
  - All original tilde expansion and pattern tests
- **Repository Security Evaluator Skill**: Created comprehensive security audit skill:
  - Elite security engineer role for vulnerability assessment
  - 10 security analysis areas (code injection, secrets, AI/LLM vulnerabilities, etc.)
  - Severity classification system (Critical/High/Medium/Low)
  - Structured audit process and reporting template
  - Special focus on hooks, patterns, and LLM prompt security
- **Initial Security Audit Report**: Comprehensive security evaluation of repository:
  - 10 findings across all severity levels (2 Critical, 2 High, 4 Medium, 3 Low)
  - Identified LLM prompt injection vulnerability (CRITICAL-001)
  - Identified ReDoS vulnerabilities in regex patterns (CRITICAL-002)
  - Detailed remediation recommendations with code examples
  - Overall risk assessment: MEDIUM
  - Documents positive security practices and defense-in-depth architecture

### Changed - Breaking Changes
- **Hook Architecture**: Migrated from single `agent-armor-security.py` to tool-specific hooks
- **Configuration Location**: Primary patterns.yaml location moved to `.claude/hooks/agent-armor/`
- **settings.json Structure**: Updated to four separate matchers (Bash, Edit, Write, Read)
- **Bash Tool**: Now has TWO hooks - command validation + LLM prompt
- **Interpreter**: Explicitly use `python3` instead of `python`

### Implementation Details
- **Hook Type**: PreToolUse hooks for Bash, Read, Write, and Edit tools (separate matchers)
- **Configuration**: Loads patterns from `.claude/hooks/agent-armor/patterns.yaml` (with fallback)
- **Path Matching**: `PathMatcher` class with:
  - Tilde (`~`) expansion to home directory
  - Glob pattern support (`*.ext`, `**/*.ext`)
  - Directory patterns (ending with `/`)
  - Case-sensitive and case-insensitive modes
  - Basename matching for patterns like `package-lock.json`
- **Security Features**:
  - Blocks 370+ dangerous bash command patterns
  - Enforces zero-access paths (credentials, keys, secrets) - **case-insensitive**
  - Enforces read-only paths (lock files, system dirs, build artifacts) - case-sensitive
  - Protects critical files from deletion (noDeletePaths)
  - Supports "ask" patterns for user confirmation
  - LLM-based security review for bash commands

### Architecture
```
.claude/
├── hooks/
│   └── agent-armor/
│       ├── bash-tool-agent-armor.py    (Bash validation)
│       ├── edit-tool-agent-armor.py    (Edit/Read validation)
│       ├── write-tool-agent-armor.py   (Write validation)
│       └── patterns.yaml               (Security patterns)
└── settings.json                       (Hook configuration)
```

### Technical Notes
- Tilde (`~`) patterns automatically expanded to user's home directory
- Supports glob patterns: `*.ext`, `**/*.ext`, directory patterns ending with `/`
- Exit code 2 blocks tool execution and provides error feedback
- Timeouts: 5 seconds for command hooks, 10 seconds for LLM prompt
- Python 3.8+ with PyYAML 6.0+ required
- Each hook is self-contained (duplicates shared classes for reliability)
- All 32 tests passing

### Migration Guide
1. New hooks automatically load patterns.yaml from new location
2. Old location (`.claude/skills/agent-armor/patterns.yaml`) checked as fallback
3. Old `agent-armor-security.py` can be removed after verification
4. No changes to patterns.yaml format/structure required

### Fixed
- Tilde (`~`) patterns properly expand to actual home directory path
- Shell configuration files protected from accidental deletion
- Case variants of security-sensitive files now properly blocked
- Read tool operations now validated against security policies
