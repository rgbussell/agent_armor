#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "pyyaml>=6.0",
# ]
# ///
"""
Agent Armor Write Tool Hook
============================

Blocks writes to protected files via PreToolUse hook on Write tool.
Loads zeroAccessPaths and readOnlyPaths from patterns.yaml.

Exit codes:
  0 = Allow write
  2 = Block write (stderr fed back to Claude)
"""

import json
import os
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


class FileAccessController:
    """Controls access to files based on path patterns."""

    def __init__(self, config: Dict):
        self.matcher = PathMatcher()
        self.zero_access_paths = config.get('zeroAccessPaths', [])
        self.read_only_paths = config.get('readOnlyPaths', [])

    def check_write_access(self, file_path: str) -> Optional[str]:
        """
        Check if file can be edited.

        Returns:
            Error message if denied, None if allowed
        """
        # Check zero-access first (highest priority, case-INSENSITIVE for security)
        matched, pattern = self.matcher.matches(file_path, self.zero_access_paths,
                                                 case_sensitive=False)
        if matched:
            return f"BLOCKED: No access allowed to '{file_path}' (matches: {pattern})"

        # Check read-only paths (case-sensitive)
        matched, pattern = self.matcher.matches(file_path, self.read_only_paths,
                                                 case_sensitive=True)
        if matched:
            return f"BLOCKED: '{file_path}' is read-only (matches: {pattern})"

        return None


def main() -> None:
    """Main hook entry point."""
    config = PatternConfig.load()

    # Read hook input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get('tool_name', '')
    tool_input = input_data.get('tool_input', {})

    # Only check Write tool
    if tool_name != 'Write':
        sys.exit(0)

    file_path = tool_input.get('file_path', '')
    if not file_path:
        sys.exit(0)

    # Check if file is blocked
    file_controller = FileAccessController(config)
    error_msg = file_controller.check_write_access(file_path)
    if error_msg:
        print(f"SECURITY: {error_msg}", file=sys.stderr)
        sys.exit(2)

    # Allow write
    sys.exit(0)


if __name__ == '__main__':
    main()
