"""Fresh-run admission and forwarding; these tests do not claim native replay."""

from contextlib import redirect_stderr
import io
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import public_ledger_source_bound_replay as binding


class SourceBoundAdmissionTests(unittest.TestCase):
    def driver(self):
        driver = ModuleType('public_ledger')

        class Native:
            def command(self, *args):
                return list(args)

        driver.Native = Native
        driver.main = mock.Mock(return_value=23)
        return driver

    def assert_refused_before_observation(self, arguments):
        driver = self.driver()
        with mock.patch.object(sys, 'argv', ['source-bound-replay', *arguments]), \
                mock.patch.dict(sys.modules, {'public_ledger': driver}), \
                mock.patch.object(Path, 'resolve', side_effect=AssertionError('repository observed')) as resolve, \
                redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as result:
                binding.main()
        self.assertEqual(result.exception.code, 2)
        resolve.assert_not_called()
        driver.main.assert_not_called()
        return errors.getvalue()

    def test_resume_and_every_stock_long_option_prefix_refuse_before_observation(self):
        for option in ('--resume', '--resum', '--resu', '--res', '--re', '--r'):
            with self.subTest(option=option):
                error = self.assert_refused_before_observation([
                    '--repo', '/unobserved-repository', 'run', '--agency', '80700',
                    '--out', '/unobserved-output', option,
                ])
                self.assertIn('--resume is not supported here', error)

    def test_attached_resume_values_cannot_reach_the_stock_driver(self):
        for option in ('--resume=false', '--resum=0', '--resu=', '--res=false', '--re=0', '--r=1'):
            with self.subTest(option=option):
                error = self.assert_refused_before_observation([
                    '--repo', '/unobserved-repository', 'run', '--out', '/unobserved-output', option,
                ])
                self.assertIn('--resume is not supported here', error)

    def test_repository_option_requires_its_exact_spelling(self):
        error = self.assert_refused_before_observation([
            '--rep', '/unobserved-repository', 'run', '--out', '/unobserved-output',
        ])
        self.assertIn('--repo', error)

    def test_non_run_action_refuses_before_observation(self):
        error = self.assert_refused_before_observation([
            '--repo', '/unobserved-repository', 'prepare', '--out', '/unobserved-output',
        ])
        self.assertIn('fresh public_ledger.py run invocation', error)

    def invoke_fresh(self, arguments):
        driver = self.driver()
        original_native = driver.Native
        with mock.patch.object(sys, 'argv', ['source-bound-replay', '--repo', '/selected-repo', *arguments]), \
                mock.patch.object(sys, 'path', list(sys.path)), \
                mock.patch.dict(sys.modules, {'public_ledger': driver}), \
                mock.patch.object(Path, 'resolve', return_value=Path('/selected-repo')) as resolve:
            result = binding.main()
        self.assertEqual(result, 23)
        resolve.assert_called_once_with(strict=True)
        driver.main.assert_called_once_with(arguments)
        self.assertTrue(issubclass(driver.Native, original_native))
        return driver.Native()

    def test_fresh_arguments_and_native_source_binding_are_preserved(self):
        arguments = ['run', '--agency', '80700', '--balance-boundary', 'agency-period',
                     '--out', '/fresh-output', '--fa', '/pinned-fa', '--fa-verify', '/pinned-verifier']
        native = self.invoke_fresh(arguments)
        prepare = ['migrate', 'import', '--action', 'prepare', '--intent', Path('source.json')]
        for _ in range(2):
            self.assertEqual(native.command(*prepare), [*prepare, '--bind-source'])
        stage = ['migrate', 'import', '--action', 'stage', '--package', 'package-oid']
        self.assertEqual(native.command(*stage), stage)

    def test_resume_like_path_values_are_forwarded_unchanged(self):
        self.invoke_fresh(['run', '--source=--resume', '--out=/fresh/--res-data', '--agency', '80700'])


if __name__ == '__main__':
    unittest.main()
