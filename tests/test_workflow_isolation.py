"""Synthetic CLI tests must not write real GitHub runner command files."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from surge_merge import auto_update, merged_update


ROOT = Path(__file__).resolve().parents[1]
PREFIX = ['env', '-u', 'GITHUB_STEP_SUMMARY', '-u', 'GITHUB_OUTPUT']


def test_commands():
    commands = {}
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        for line in path.read_text().splitlines():
            if 'python3 -m unittest discover' in line:
                commands[path.name] = line.strip().removeprefix('run: ')
    return commands


class WorkflowIsolationTests(unittest.TestCase):
    def test_every_workflow_test_command_is_isolated(self):
        commands = test_commands()
        self.assertEqual(set(commands), {'ci.yml', 'update.yml', 'update-merged.yml'})
        for name, command in commands.items():
            with self.subTest(workflow=name):
                self.assertEqual(shlex.split(command), PREFIX +
                                 ['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v'])

    def run_workflow_commands(self, exit_code):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            summary, output = root / 'job-summary', root / 'step-output'
            summary.write_text('existing real summary\n')
            output.write_text('existing real output\n')
            python = root / 'python3'
            python.write_text('#!/bin/sh\n'
                              '[ -z "${GITHUB_STEP_SUMMARY+x}" ] || exit 91\n'
                              '[ -z "${GITHUB_OUTPUT+x}" ] || exit 92\n'
                              'exit "$SYNTHETIC_TEST_EXIT"\n')
            python.chmod(0o755)
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get('PATH', ''),
                               GITHUB_STEP_SUMMARY=str(summary), GITHUB_OUTPUT=str(output),
                               SYNTHETIC_TEST_EXIT=str(exit_code))
            for name, command in test_commands().items():
                with self.subTest(workflow=name, exit_code=exit_code):
                    result = subprocess.run(['bash', '-e', '-c', command], env=environment,
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, exit_code, result.stderr)
                    self.assertEqual(summary.read_text(), 'existing real summary\n')
                    self.assertEqual(output.read_text(), 'existing real output\n')

    def test_workflow_tests_leave_runner_files_untouched(self):
        self.run_workflow_commands(0)

    def test_test_failures_remain_failures(self):
        self.run_workflow_commands(23)

    def test_real_update_steps_still_emit_summary_and_outputs(self):
        # Isolation belongs only to the unittest subprocess, not the reporter.
        for module in (auto_update, merged_update):
            with self.subTest(updater=module.__name__), tempfile.TemporaryDirectory() as folder:
                summary, output = Path(folder) / 'summary', Path(folder) / 'output'
                with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary),
                                             'GITHUB_OUTPUT': str(output)}), redirect_stdout(io.StringIO()):
                    module.emit_status({'status': 'ready', 'package_sha256': 'a' * 64})
                self.assertIn('Status: ready', summary.read_text())
                self.assertEqual(output.read_text(), 'changed=true\npackage_sha256=' + 'a' * 64 + '\n')


if __name__ == '__main__':
    unittest.main()
