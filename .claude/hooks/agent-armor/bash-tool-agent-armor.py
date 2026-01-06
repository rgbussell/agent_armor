#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "pyyaml>=6.0",
# ]
# ///
"""
Agent Armor Bash Tool Hook
===========================

Protects against dangerous bash commands via PreToolUse hook on Bash tool.
Loads bashToolPatterns, zeroAccessPaths, and noDeletePaths from patterns.yaml.

Exit codes:
  0 = Allow command or asking for confirmation (check stdout for JSON)
  2 = Block command (stderr fed back to Claude)
"""

import json
import os
import re
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


class PatternConfig:
    """Loads and caches patterns.yaml configuration with multi-path fallback."""

    _config: Optional[Dict] = None
    _config_path: Optional[Path] = None

    @classmethod
    def load(cls) -> Dict:
        """Load patterns from YAML file with caching and multi-path fallback."""
        if cls._config is not None:
            return cls._config

        # Priority 1: New location - hooks/agent-armor/patterns.yaml
        project_dir = Path(os.environ.get('CLAUDE_PROJECT_DIR', '.'))
        new_location = project_dir / '.claude' / 'hooks' / 'agent-armor' / 'patterns.yaml'

        # Priority 2: Old location - skills/agent-armor/patterns.yaml (backward compat)
        old_location = project_dir / '.claude' / 'skills' / 'agent-armor' / 'patterns.yaml'

        # Priority 3: Script directory (installed location)
        script_dir = Path(__file__).parent
        script_location = script_dir / 'patterns.yaml'

        # Check in priority order
        for config_path in [new_location, old_location, script_location]:
            if config_path.exists():
                cls._config_path = config_path
                break

        if not cls._config_path:
            # No config found - return empty structure
            return cls._empty_config()

        try:
            with open(cls._config_path, 'r') as f:
                cls._config = yaml.safe_load(f) or {}
            return cls._config
        except yaml.YAMLError as e:
            print(f"ERROR parsing patterns.yaml: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"ERROR loading patterns.yaml: {e}", file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def _empty_config() -> Dict:
        """Return empty configuration structure."""
        return {
            'zeroAccessPaths': [],
            'readOnlyPaths': [],
            'noDeletePaths': [],
            'bashToolPatterns': []
        }


class PathMatcher:
    """
    Matches file paths against glob patterns with tilde expansion.

    Handles:
    - Tilde (~) expansion to home directory
    - Glob patterns (*.ext, **/*.ext)
    - Absolute and relative paths
    - Directory patterns ending with /
    - Case-sensitive and case-insensitive matching
    """

    def __init__(self):
        self.home_dir = str(Path.home())

    def expand_tilde(self, pattern: str) -> str:
        """
        Expand ~ to actual home directory path.

        Examples:
            ~/.ssh/ -> /home/username/.ssh/
            ~/file.txt -> /home/username/file.txt
        """
        if pattern.startswith('~/'):
            return os.path.join(self.home_dir, pattern[2:])
        elif pattern == '~':
            return self.home_dir
        return pattern

    def matches(self, file_path: str, patterns: List[str],
                case_sensitive: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Check if file_path matches any pattern.

        Args:
            file_path: The file path to check
            patterns: List of patterns to match against
            case_sensitive: If False, use case-insensitive matching (for security)

        Returns:
            (matched, pattern): Tuple of (whether matched, which pattern matched)
        """
        # Normalize the file path
        try:
            abs_path = str(Path(file_path).resolve())
        except Exception:
            abs_path = file_path

        # For case-insensitive matching, convert to lowercase
        if not case_sensitive:
            abs_path_cmp = abs_path.lower()
            file_path_cmp = file_path.lower()
        else:
            abs_path_cmp = abs_path
            file_path_cmp = file_path

        for pattern in patterns:
            # Expand tilde in pattern
            expanded_pattern = self.expand_tilde(pattern)

            # For case-insensitive, convert pattern too
            if not case_sensitive:
                expanded_pattern_cmp = expanded_pattern.lower()
                pattern_cmp = pattern.lower()
            else:
                expanded_pattern_cmp = expanded_pattern
                pattern_cmp = pattern

            # Check for directory pattern (ends with /)
            if expanded_pattern.endswith('/'):
                # Match if file is within this directory
                if abs_path_cmp.startswith(expanded_pattern_cmp):
                    return True, pattern
                # Also check without trailing slash
                dir_path_cmp = expanded_pattern_cmp.rstrip('/')
                if abs_path_cmp.startswith(dir_path_cmp + os.sep):
                    return True, pattern

            # Check for glob patterns OR basename patterns (no path separator)
            has_glob = '*' in expanded_pattern or '?' in expanded_pattern
            is_basename_pattern = os.sep not in expanded_pattern and '/' not in expanded_pattern

            if has_glob or is_basename_pattern:
                if self._glob_match(abs_path_cmp, expanded_pattern_cmp, case_sensitive):
                    return True, pattern
                # Also try matching the original relative path
                if self._glob_match(file_path_cmp, expanded_pattern_cmp, case_sensitive):
                    return True, pattern
            else:
                # Exact match for full paths
                if abs_path_cmp == expanded_pattern_cmp or file_path_cmp == expanded_pattern_cmp:
                    return True, pattern

        return False, None

    @staticmethod
    def _glob_match(path: str, pattern: str, case_sensitive: bool) -> bool:
        """Match path against glob pattern."""
        # Handle ** for recursive directory matching
        if '**' in pattern:
            # Convert ** pattern to regex-like matching
            pattern_parts = pattern.split('**')
            if len(pattern_parts) == 2:
                prefix, suffix = pattern_parts
                # Match if path starts with prefix and ends with suffix pattern
                if prefix and not path.startswith(prefix.rstrip('/')):
                    return False
                if suffix:
                    suffix_pattern = suffix.lstrip('/')
                    # Check if any tail portion matches the suffix
                    path_parts = path.split(os.sep)
                    for i in range(len(path_parts)):
                        tail = os.sep.join(path_parts[i:])
                        if fnmatch(tail, suffix_pattern):
                            return True
                    return False
                return True

        # If pattern has no path separator, match against basename only
        if os.sep not in pattern and '/' not in pattern:
            basename = os.path.basename(path)
            return fnmatch(basename, pattern)

        # Standard glob matching for full paths
        return fnmatch(path, pattern)


class BashCommandValidator:
    """Validates bash commands against security patterns."""

    def __init__(self, patterns: List[Dict]):
        self.patterns = self._compile_patterns(patterns)

    @staticmethod
    def _compile_patterns(patterns: List) -> List[Tuple[re.Pattern, Dict]]:
        """Compile regex patterns from config."""
        compiled = []
        for item in patterns:
            if isinstance(item, dict):
                pattern_str = item.get('pattern', '')
                if pattern_str:
                    try:
                        pattern = re.compile(pattern_str)
                        compiled.append((pattern, item))
                    except re.error as e:
                        print(f"WARNING: Invalid regex '{pattern_str}': {e}", file=sys.stderr)
        return compiled

    def check(self, command: str) -> Tuple[bool, Optional[str], bool]:
        """
        Check command against patterns.

        Returns:
            (is_blocked, reason, requires_ask): Tuple indicating if command is blocked,
            the reason, and whether it requires user confirmation
        """
        for pattern, config in self.patterns:
            if pattern.search(command):
                reason = config.get('reason', 'Matched security pattern')
                ask = config.get('ask', False)

                if ask:
                    # This pattern requires user confirmation
                    return False, reason, True
                else:
                    # This pattern blocks the command
                    return True, reason, False

        return False, None, False


class FileAccessController:
    """Controls access to files based on path patterns."""

    def __init__(self, config: Dict):
        self.matcher = PathMatcher()
        self.zero_access_paths = config.get('zeroAccessPaths', [])
        self.no_delete_paths = config.get('noDeletePaths', [])

    def check_delete_access(self, command: str, file_path: str = None) -> Optional[str]:
        """
        Check if file can be deleted via bash command.

        Returns:
            Error message if denied, None if allowed
        """
        # If specific file path provided, check it
        if file_path:
            paths_to_check = [file_path]
        else:
            # Extract paths from rm/rmdir commands
            paths_to_check = self._extract_delete_paths(command)

        for path in paths_to_check:
            # Check zero-access first (case-insensitive for security)
            matched, pattern = self.matcher.matches(path, self.zero_access_paths,
                                                     case_sensitive=False)
            if matched:
                return f"BLOCKED: No access to '{path}' (matches: {pattern})"

            # Check no-delete paths (case-sensitive)
            matched, pattern = self.matcher.matches(path, self.no_delete_paths,
                                                     case_sensitive=True)
            if matched:
                return f"BLOCKED: Cannot delete '{path}' (matches: {pattern})"

        return None

    @staticmethod
    def _extract_delete_paths(command: str) -> List[str]:
        """Extract file paths from rm/rmdir commands."""
        paths = []

        # Simple extraction - look for rm/rmdir followed by paths
        # This is basic and could be improved
        tokens = command.split()
        found_rm = False
        for token in tokens:
            if token in ('rm', 'rmdir'):
                found_rm = True
            elif found_rm and not token.startswith('-'):
                # This looks like a path
                paths.append(token)

        return paths


def main() -> None:
    """Main hook entry point."""
    config = PatternConfig.load()

    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get('tool_name', '')
    tool_input = input_data.get('tool_input', {})

    # Only check Bash tool
    if tool_name != 'Bash':
        sys.exit(0)

    command = tool_input.get('command', '')
    if not command:
        sys.exit(0)

    # Add length check to prevent ReDoS attacks
    MAX_COMMAND_LENGTH = 100000  # 100KB
    if len(command) > MAX_COMMAND_LENGTH:
        print(f"ERROR: Command exceeds maximum length ({MAX_COMMAND_LENGTH} chars)", file=sys.stderr)
        print("SECURITY: Potential ReDoS attack detected", file=sys.stderr)
        sys.exit(2)

    # Check bash command patterns
    bash_patterns = config.get('bashToolPatterns', [])
    validator = BashCommandValidator(bash_patterns)
    is_blocked, reason, requires_ask = validator.check(command)

    if is_blocked:
        print(f"SECURITY VIOLATION: {reason}", file=sys.stderr)
        print(f"Command blocked: {command}", file=sys.stderr)
        sys.exit(2)  # Exit code 2 blocks the tool call

    if requires_ask:
        # For now, treat "ask" patterns as blocked with explanation
        # Future: Could integrate with Claude's approval system
        print(f"APPROVAL REQUIRED: {reason}", file=sys.stderr)
        print(f"Command: {command}", file=sys.stderr)
        print(f"This command requires user confirmation before execution.", file=sys.stderr)
        sys.exit(2)

    # Check for file deletions in bash commands
    if 'rm' in command or 'rmdir' in command:
        file_controller = FileAccessController(config)
        error_msg = file_controller.check_delete_access(command)
        if error_msg:
            print(f"SECURITY: {error_msg}", file=sys.stderr)
            sys.exit(2)

    # All checks passed - allow command
    sys.exit(0)


if __name__ == '__main__':
    main()
