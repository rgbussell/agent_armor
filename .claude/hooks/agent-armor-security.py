#!/usr/bin/env python3
"""
Agent Armor Security Hook
Protects against dangerous commands and unauthorized file access.

This hook:
1. Blocks dangerous bash commands based on patterns
2. Enforces zero-access paths (no read/write/edit)
3. Enforces read-only paths (no write/edit)
4. Protects critical files from deletion
5. Prompts user for confirmation on "ask" patterns
6. Properly expands ~ to home directory in all path patterns
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


class PatternConfig:
    """Loads and caches patterns.yaml configuration."""

    _config: Optional[Dict] = None
    _config_path: Optional[Path] = None

    @classmethod
    def load(cls) -> Dict:
        """Load patterns from YAML file with caching."""
        if cls._config is not None:
            return cls._config

        # Find patterns.yaml - check skill directory first
        project_dir = Path(os.environ.get('CLAUDE_PROJECT_DIR', '.'))
        possible_paths = [
            project_dir / '.claude' / 'skills' / 'agent-armor' / 'patterns.yaml',
            project_dir / '.claude' / 'hooks' / 'patterns.yaml',
            project_dir / 'patterns.yaml',
        ]

        cls._config_path = None
        for path in possible_paths:
            if path.exists():
                cls._config_path = path
                break

        if not cls._config_path:
            print(f"WARNING: patterns.yaml not found. Checked: {possible_paths}", file=sys.stderr)
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
            'bashToolPatterns': [],
            'zeroAccessPaths': [],
            'readOnlyPaths': [],
            'noDeletePaths': []
        }


class PathMatcher:
    """
    Matches file paths against glob patterns with tilde expansion.

    Handles:
    - Tilde (~) expansion to home directory
    - Glob patterns (*.ext, **/*.ext)
    - Absolute and relative paths
    - Directory patterns ending with /
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

    def matches(self, file_path: str, patterns: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Check if file_path matches any pattern.

        Returns:
            (matched, pattern): Tuple of (whether matched, which pattern matched)
        """
        # Normalize the file path
        try:
            abs_path = str(Path(file_path).resolve())
        except Exception:
            abs_path = file_path

        for pattern in patterns:
            # Expand tilde in pattern
            expanded_pattern = self.expand_tilde(pattern)

            # Check for directory pattern (ends with /)
            if expanded_pattern.endswith('/'):
                # Match if file is within this directory
                if abs_path.startswith(expanded_pattern):
                    return True, pattern
                # Also check without trailing slash
                dir_path = expanded_pattern.rstrip('/')
                if abs_path.startswith(dir_path + os.sep):
                    return True, pattern

            # Check for glob patterns OR basename patterns (no path separator)
            has_glob = '*' in expanded_pattern or '?' in expanded_pattern
            is_basename_pattern = os.sep not in expanded_pattern and '/' not in expanded_pattern

            if has_glob or is_basename_pattern:
                if self._glob_match(abs_path, expanded_pattern):
                    return True, pattern
                # Also try matching the original relative path
                if self._glob_match(file_path, expanded_pattern):
                    return True, pattern
            else:
                # Exact match for full paths
                if abs_path == expanded_pattern or file_path == expanded_pattern:
                    return True, pattern

        return False, None

    @staticmethod
    def _glob_match(path: str, pattern: str) -> bool:
        """Match path against glob pattern."""
        from fnmatch import fnmatch

        # Handle ** for recursive directory matching
        if '**' in pattern:
            # Convert ** pattern to regex
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
        self.read_only_paths = config.get('readOnlyPaths', [])
        self.no_delete_paths = config.get('noDeletePaths', [])

    def check_read_access(self, file_path: str) -> Optional[str]:
        """
        Check if file can be read.

        Returns:
            Error message if denied, None if allowed
        """
        matched, pattern = self.matcher.matches(file_path, self.zero_access_paths)
        if matched:
            return f"BLOCKED: No access allowed to '{file_path}' (matches: {pattern})"

        return None

    def check_write_access(self, file_path: str) -> Optional[str]:
        """
        Check if file can be written or edited.

        Returns:
            Error message if denied, None if allowed
        """
        # Check zero-access first (highest priority)
        matched, pattern = self.matcher.matches(file_path, self.zero_access_paths)
        if matched:
            return f"BLOCKED: No access allowed to '{file_path}' (matches: {pattern})"

        # Check read-only paths
        matched, pattern = self.matcher.matches(file_path, self.read_only_paths)
        if matched:
            return f"BLOCKED: '{file_path}' is read-only (matches: {pattern})"

        return None

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
            # Check zero-access first
            matched, pattern = self.matcher.matches(path, self.zero_access_paths)
            if matched:
                return f"BLOCKED: No access to '{path}' (matches: {pattern})"

            # Check no-delete paths
            matched, pattern = self.matcher.matches(path, self.no_delete_paths)
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


def main():
    """Main hook entry point."""
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get('tool_name', '')
    tool_input = input_data.get('tool_input', {})

    # Load configuration
    config = PatternConfig.load()

    # Handle different tool types
    if tool_name == 'Bash':
        command = tool_input.get('command', '')
        if not command:
            sys.exit(0)

        # Check bash command patterns
        bash_patterns = config.get('bashToolPatterns', [])
        validator = BashCommandValidator(bash_patterns)
        is_blocked, reason, requires_ask = validator.check(command)

        if is_blocked:
            print(f"SECURITY VIOLATION: {reason}", file=sys.stderr)
            print(f"Command blocked: {command}", file=sys.stderr)
            sys.exit(2)  # Exit code 2 blocks the tool call

        if requires_ask:
            # For now, treat "ask" patterns as blocked
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
                print(error_msg, file=sys.stderr)
                sys.exit(2)

    elif tool_name == 'Read':
        file_path = tool_input.get('file_path', '')
        if not file_path:
            sys.exit(0)

        file_controller = FileAccessController(config)
        error_msg = file_controller.check_read_access(file_path)
        if error_msg:
            print(error_msg, file=sys.stderr)
            sys.exit(2)

    elif tool_name in ('Write', 'Edit'):
        file_path = tool_input.get('file_path', '')
        if not file_path:
            sys.exit(0)

        file_controller = FileAccessController(config)
        error_msg = file_controller.check_write_access(file_path)
        if error_msg:
            print(error_msg, file=sys.stderr)
            sys.exit(2)

    # All checks passed
    sys.exit(0)


if __name__ == '__main__':
    main()
