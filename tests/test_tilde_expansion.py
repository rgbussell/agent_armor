#!/usr/bin/env python3
"""
Test suite for Agent Armor security hook with focus on tilde expansion.

SAFETY GUARANTEE:
==================
This test suite ONLY tests the pattern matching logic of the security hook.
It does NOT execute any of the dangerous commands being tested.

How it works:
1. Test sends JSON input to the hook script (agent-armor-security.py)
2. Hook script performs PATTERN MATCHING ONLY
3. Hook returns exit code (0=allow, 2=block)
4. Test verifies the exit code matches expectations

NO COMMANDS ARE EVER EXECUTED - only pattern matched.

Tests:
1. Tilde expansion in path patterns
2. Pattern matching with expanded paths
3. Bash command blocking
4. File access control
"""

import json
import os
import subprocess
import sys
from pathlib import Path


# ANSI color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


class TestRunner:
    """Run security hook tests - PATTERN MATCHING ONLY, no command execution."""

    def __init__(self):
        self.passed = 0
        self.failed = 0

        # Tool-specific hooks (new architecture)
        base_path = Path(__file__).parent.parent / '.claude' / 'hooks' / 'agent-armor'
        self.bash_hook = base_path / 'bash-tool-agent-armor.py'
        self.edit_hook = base_path / 'edit-tool-agent-armor.py'
        self.write_hook = base_path / 'write-tool-agent-armor.py'

        # Verify all hooks exist
        for hook_name, hook_path in [('Bash', self.bash_hook), ('Edit', self.edit_hook), ('Write', self.write_hook)]:
            if not hook_path.exists():
                print(f"{RED}ERROR: {hook_name} hook not found at {hook_path}{RESET}")
                sys.exit(1)

        # SAFETY: Verify hook scripts don't contain dangerous execution patterns
        self._verify_hook_safety()

    def _verify_hook_safety(self):
        """
        Safety check: Ensure hook scripts don't execute commands.

        This is a paranoid safety check to ensure the hooks only do pattern
        matching and never actually execute the commands they're testing.
        """
        # Check all three hooks
        for hook_name, hook_path in [('Bash', self.bash_hook), ('Edit', self.edit_hook), ('Write', self.write_hook)]:
            with open(hook_path, 'r') as f:
                hook_content = f.read()

            # Check for dangerous patterns that would indicate command execution
            dangerous_patterns = [
                'subprocess.call',
                'subprocess.Popen',
                'os.system',
                'os.popen',
                'exec(',
                'eval(',
                '__import__',
            ]

            found_dangerous = []
            for pattern in dangerous_patterns:
                if pattern in hook_content:
                    # Filter out comments and strings
                    lines = hook_content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if pattern in line and not line.strip().startswith('#'):
                            found_dangerous.append(f"{hook_name} Line {i}: {line.strip()}")

            if found_dangerous:
                print(f"{RED}SAFETY ERROR: {hook_name} hook contains dangerous patterns:{RESET}")
                for item in found_dangerous:
                    print(f"  {item}")
                print(f"\n{RED}Hook scripts should ONLY do pattern matching, never execute commands.{RESET}")
                sys.exit(1)

        print(f"{BLUE}✓ Safety check passed: All hook scripts contain no command execution{RESET}")

    def run_hook(self, tool_name: str, tool_input: dict) -> tuple:
        """
        Run the security hook with given input.

        IMPORTANT: This only runs the HOOK SCRIPT (pattern matcher).
        It does NOT execute the actual command being tested.

        The hook receives JSON describing a hypothetical tool call and
        returns whether it would be blocked (exit 2) or allowed (exit 0).

        Returns:
            (exit_code, stdout, stderr)
        """
        # Select appropriate hook based on tool_name
        if tool_name == 'Bash':
            hook_path = self.bash_hook
        elif tool_name == 'Edit':
            hook_path = self.edit_hook
        elif tool_name == 'Write':
            hook_path = self.write_hook
        elif tool_name == 'Read':
            # Read uses the Edit hook logic (zero-access and read-only checks)
            hook_path = self.edit_hook
        else:
            hook_path = self.bash_hook  # Fallback

        input_data = {
            'tool_name': tool_name,
            'tool_input': tool_input
        }

        input_json = json.dumps(input_data)

        # SAFETY: We only run the hook script, not the command being tested
        result = subprocess.run(
            ['python3', str(hook_path)],  # Only the hook script
            input=input_json,               # JSON input, not shell commands
            capture_output=True,
            text=True,
            env={**os.environ, 'CLAUDE_PROJECT_DIR': str(Path(__file__).parent.parent)}
        )

        return result.returncode, result.stdout, result.stderr

    def test(self, name: str, tool_name: str, tool_input: dict,
             should_block: bool, expected_msg: str = None):
        """
        Run a single test case.

        SAFETY: This tests the hook's pattern matching logic only.
        No actual commands are executed.

        Args:
            name: Test name
            tool_name: Tool being tested (Bash, Read, Write, Edit)
            tool_input: Tool input parameters (command or file_path)
            should_block: Whether the hook should block this action (exit code 2)
            expected_msg: Expected message in stderr (optional)
        """
        exit_code, stdout, stderr = self.run_hook(tool_name, tool_input)

        # Check if blocked as expected
        is_blocked = (exit_code == 2)
        success = (is_blocked == should_block)

        # If expecting a message, check for it
        if expected_msg and success:
            if expected_msg.lower() not in stderr.lower():
                success = False

        if success:
            print(f"{GREEN}✓{RESET} {name}")
            self.passed += 1
        else:
            print(f"{RED}✗{RESET} {name}")
            print(f"  Expected block={should_block}, got exit_code={exit_code}")
            if stderr:
                print(f"  stderr: {stderr.strip()}")
            self.failed += 1

    def print_summary(self):
        """Print test summary."""
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Tests: {total} total, {GREEN}{self.passed} passed{RESET}, " +
              f"{RED if self.failed > 0 else GREEN}{self.failed} failed{RESET}")
        print(f"{'='*60}")

        if self.failed > 0:
            sys.exit(1)


def main():
    """Run all tests."""
    print("Agent Armor Security Hook Tests")
    print("="*60)
    print(f"{BLUE}SAFETY: Tests only verify pattern matching logic{RESET}")
    print(f"{BLUE}        NO commands are actually executed{RESET}")
    print("="*60)

    runner = TestRunner()
    home = str(Path.home())

    # =========================================================================
    # TILDE EXPANSION TESTS
    # =========================================================================
    print(f"\n{YELLOW}Testing Tilde Expansion{RESET}")

    runner.test(
        "Block read access to ~/.ssh/ (tilde expansion)",
        "Read",
        {"file_path": f"{home}/.ssh/id_rsa"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block read access to ~/.aws/ (tilde expansion)",
        "Read",
        {"file_path": f"{home}/.aws/credentials"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block write access to ~/.ssh/ (tilde expansion)",
        "Write",
        {"file_path": f"{home}/.ssh/config"},
        should_block=True,
        expected_msg="No access"
    )

    # =========================================================================
    # BASH COMMAND PATTERN TESTS
    # =========================================================================
    print(f"\n{YELLOW}Testing Bash Command Patterns (Pattern Matching Only){RESET}")

    # SAFETY NOTE: These commands look dangerous, but they are NEVER executed.
    # We only test if the hook's pattern matching correctly identifies them.

    runner.test(
        "Block 'rm -rf /'",
        "Bash",
        {"command": "rm -rf /"},
        should_block=True,
        expected_msg="recursive"
    )

    runner.test(
        "Block 'sudo rm -rf'",
        "Bash",
        {"command": "sudo rm -rf /tmp/test"},
        should_block=True,
        expected_msg="sudo rm"
    )

    runner.test(
        "Block 'git reset --hard'",
        "Bash",
        {"command": "git reset --hard HEAD~1"},
        should_block=True,
        expected_msg="git reset --hard"
    )

    runner.test(
        "Block 'git push --force'",
        "Bash",
        {"command": "git push origin main --force"},
        should_block=True,
        expected_msg="force"
    )

    runner.test(
        "Allow 'git push --force-with-lease'",
        "Bash",
        {"command": "git push origin main --force-with-lease"},
        should_block=False
    )

    runner.test(
        "Block 'chmod 777'",
        "Bash",
        {"command": "chmod 777 file.txt"},
        should_block=True,
        expected_msg="777"
    )

    runner.test(
        "Block 'terraform destroy'",
        "Bash",
        {"command": "terraform destroy -auto-approve"},
        should_block=True,
        expected_msg="terraform destroy"
    )

    runner.test(
        "Block 'aws s3 rm --recursive'",
        "Bash",
        {"command": "aws s3 rm s3://bucket --recursive"},
        should_block=True,
        expected_msg="recursive"
    )

    runner.test(
        "Block 'DROP DATABASE'",
        "Bash",
        {"command": "psql -c 'DROP DATABASE production'"},
        should_block=True,
        expected_msg="DROP DATABASE"
    )

    runner.test(
        "Allow safe git commands",
        "Bash",
        {"command": "git status"},
        should_block=False
    )

    runner.test(
        "Allow safe file operations",
        "Bash",
        {"command": "ls -la"},
        should_block=False
    )

    # =========================================================================
    # ZERO ACCESS PATHS TESTS
    # =========================================================================
    print(f"\n{YELLOW}Testing Zero Access Paths{RESET}")

    # SAFETY: Using non-existent paths - even if something went wrong,
    # these paths don't exist so nothing could be affected
    runner.test(
        "Block read of .env file",
        "Read",
        {"file_path": "/nonexistent/project/.env"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block write of .env.local file",
        "Write",
        {"file_path": "/nonexistent/project/.env.local"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block read of *.pem file",
        "Read",
        {"file_path": "/nonexistent/cert.pem"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block read of service account JSON",
        "Read",
        {"file_path": "/nonexistent/my-project-serviceAccount.json"},
        should_block=True,
        expected_msg="No access"
    )

    # =========================================================================
    # READ-ONLY PATHS TESTS
    # =========================================================================
    print(f"\n{YELLOW}Testing Read-Only Paths{RESET}")

    runner.test(
        "Allow read of package-lock.json",
        "Read",
        {"file_path": "/nonexistent/project/package-lock.json"},
        should_block=False
    )

    runner.test(
        "Block write of package-lock.json",
        "Write",
        {"file_path": "/nonexistent/project/package-lock.json"},
        should_block=True,
        expected_msg="read-only"
    )

    runner.test(
        "Block edit of yarn.lock",
        "Edit",
        {"file_path": "/nonexistent/project/yarn.lock"},
        should_block=True,
        expected_msg="read-only"
    )

    runner.test(
        "Block write to /etc/hosts",
        "Write",
        {"file_path": "/etc/hosts"},
        should_block=True,
        expected_msg="read-only"
    )

    # =========================================================================
    # SAFE OPERATIONS TESTS
    # =========================================================================
    print(f"\n{YELLOW}Testing Safe Operations (Should Allow){RESET}")

    runner.test(
        "Allow read of regular file",
        "Read",
        {"file_path": "/nonexistent/project/src/index.js"},
        should_block=False
    )

    runner.test(
        "Allow write of regular file",
        "Write",
        {"file_path": "/nonexistent/project/src/index.js"},
        should_block=False
    )

    runner.test(
        "Allow edit of regular file",
        "Edit",
        {"file_path": "/nonexistent/project/README.md"},
        should_block=False
    )

    # =========================================================================
    # CASE-INSENSITIVE SECURITY MATCHING TESTS (new feature)
    # =========================================================================
    print(f"\n{YELLOW}Testing Case-Insensitive Security Matching{RESET}")

    runner.test(
        "Block .ENV (uppercase) - case-insensitive security",
        "Read",
        {"file_path": "/nonexistent/project/.ENV"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block .Env (mixed case) - case-insensitive security",
        "Write",
        {"file_path": "/nonexistent/project/.Env"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block ~/.SSH/id_rsa (uppercase directory) - case-insensitive",
        "Read",
        {"file_path": f"{home}/.SSH/id_rsa"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Block cert.PEM (uppercase extension) - case-insensitive",
        "Edit",
        {"file_path": "/nonexistent/cert.PEM"},
        should_block=True,
        expected_msg="No access"
    )

    runner.test(
        "Allow PACKAGE-LOCK.JSON (uppercase) - read-only is case-sensitive, so uppercase doesn't match",
        "Write",
        {"file_path": "/nonexistent/project/PACKAGE-LOCK.JSON"},
        should_block=False  # Read-only paths are case-sensitive, uppercase won't match
    )

    # =========================================================================
    # SHELL CONFIG PROTECTION TESTS (from patterns.yaml update)
    # =========================================================================
    print(f"\n{YELLOW}Testing Shell Config Protection{RESET}")

    runner.test(
        "Block delete of ~/.bashrc",
        "Bash",
        {"command": f"rm {home}/.bashrc"},
        should_block=True,
        expected_msg="Cannot delete"
    )

    runner.test(
        "Block delete of ~/.zshrc",
        "Bash",
        {"command": f"rm {home}/.zshrc"},
        should_block=True,
        expected_msg="Cannot delete"
    )

    # Print summary
    runner.print_summary()


if __name__ == '__main__':
    main()
