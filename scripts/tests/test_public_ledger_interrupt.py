"""Controlled-interruption orchestration guards; no native replay is claimed here."""

from contextlib import redirect_stderr
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import public_ledger as replay
import public_ledger_interrupt as interrupt


class ControlledInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.output = self.directory / 'output'
        (self.output / 'recovery').mkdir(parents=True)
        self.marker = self.directory / 'interruption.json'
        self.driver_path = Path(replay.__file__)
        self.write_pins({'format': 'fa-public-ledger-recovery-v1', 'bind_source': True})
        self.prepare = ('migrate', 'import', '--action', 'prepare', '--intent',
                        self.directory / 'exact-source.json', '--bind-source')
        self.receipt = {
            'event': 'migration_import_prepared',
            'data': {'package_oid': '12' * 32, 'run_state': 'Open', 'recorded_count': 0,
                     'already_recorded': False, 'source_binding': None,
                     'source_binding_receipt': None, 'chunks': [
                         {'index': 0, 'recorded_at': None}, {'index': 1, 'recorded_at': None},
                     ]},
        }

    def write_pins(self, value):
        record = {'sha256': hashlib.sha256(replay.json_bytes(value)).hexdigest(), 'value': value}
        (self.output / 'recovery/pins.json').write_text(json.dumps(record), encoding='utf-8')

    def invoke(self, boundary='after-package-before-bind', *, command=None, receipt=None,
               kwargs=None, native_error=None):
        command = self.prepare if command is None else command
        receipt = self.receipt if receipt is None else receipt
        kwargs = {} if kwargs is None else kwargs
        calls = []
        failures = []

        class Native:
            def call(native, *arguments, **options):
                calls.append((arguments, options))
                if native_error is not None:
                    raise native_error
                return copy.deepcopy(receipt)

        ordinary = Native.call
        native = Native()
        native.output = self.output

        def driver_main(arguments):
            self.assertEqual(arguments, ['run', '--out', str(self.output), '--bind-source'])
            try:
                native.call(*command, **kwargs)
            except replay.ReplayError as error:
                failures.append(str(error))
                return 1
            return 0

        driver = SimpleNamespace(Native=Native, main=driver_main, require=replay.require,
                                 read_fact=replay.read_fact, ReplayError=replay.ReplayError)
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        arguments = ['--driver', str(self.driver_path), '--boundary', boundary,
                     '--marker', str(self.marker), '--', 'run', '--out', str(self.output),
                     '--bind-source']
        with mock.patch.object(interrupt.importlib.util, 'spec_from_file_location', return_value=spec), \
                mock.patch.object(interrupt.importlib.util, 'module_from_spec', return_value=driver), \
                mock.patch.object(sys, 'path', list(sys.path)), redirect_stderr(io.StringIO()):
            result = interrupt.main(arguments)
        self.assertIs(Native.call, ordinary, 'the driver method must be restored after every outcome')
        marker = json.loads(self.marker.read_text()) if self.marker.exists() else None
        return result, calls, failures, marker

    def test_package_gap_executes_only_unbound_prepare_and_retains_actual_receipt(self):
        options = {'input_text': 'exact input bytes\n'}
        result, calls, failures, marker = self.invoke(kwargs=options)
        self.assertEqual(result, 1)
        self.assertEqual(calls, [(self.prepare[:-1], options)])
        self.assertIn('intentional native interruption: after-package-before-bind', failures[0])
        self.assertEqual(marker['requested_arguments'], list(map(str, self.prepare)))
        self.assertEqual(marker['executed_arguments'], list(map(str, self.prepare[:-1])))
        self.assertEqual(marker['native_receipt'], self.receipt)
        self.assertIs(marker['source_binding_expected_on_resume'], True)
        self.assertIn('not a native internal crash', marker['scope'])
        self.assertEqual(marker['pins_sha256'], interrupt.sha256(self.output / 'recovery/pins.json'))
        self.assertEqual(marker['driver_sha256'], interrupt.sha256(self.driver_path))
        self.assertEqual(marker['interruption_helper_sha256'], interrupt.sha256(Path(interrupt.__file__)))

    def test_gap_refuses_missing_duplicate_or_attached_binding_switch_before_native_call(self):
        base = self.prepare[:-1]
        for suffix in ((), ('--bind-source', '--bind-source'), ('--bind-source=true',),
                       ('--bind-source', '--bind-source=false')):
            with self.subTest(suffix=suffix):
                result, calls, failures, marker = self.invoke(command=base + suffix)
                self.assertEqual(result, 1)
                self.assertEqual(calls, [])
                self.assertIn('exactly one canonical --bind-source', failures[0])
                self.assertIsNone(marker)

    def test_gap_requires_original_bound_pin_before_native_call(self):
        for value in ({'format': 'fa-public-ledger-recovery-v1'},
                      {'format': 'fa-public-ledger-recovery-v1', 'bind_source': False},
                      {'format': 'fa-public-ledger-recovery-v1', 'bind_source': 1},
                      {'format': 'unknown', 'bind_source': True}):
            with self.subTest(value=value):
                self.write_pins(value)
                result, calls, failures, marker = self.invoke()
                self.assertEqual(result, 1)
                self.assertEqual(calls, [])
                self.assertIn('originally source-bound run', failures[0])
                self.assertIsNone(marker)

    def test_gap_checks_pin_envelope_checksum_before_native_call(self):
        path = self.output / 'recovery/pins.json'
        record = json.loads(path.read_text())
        record['value']['agency'] = '20400'
        path.write_text(json.dumps(record), encoding='utf-8')
        result, calls, failures, marker = self.invoke()
        self.assertEqual(result, 1)
        self.assertEqual(calls, [])
        self.assertIn('recovery checkpoint checksum differs', failures[0])
        self.assertIsNone(marker)

    def test_gap_does_not_label_bound_staged_retried_or_malformed_receipt_as_interruption(self):
        changes = [
            {'run_state': 'Finalized'}, {'recorded_count': 1}, {'recorded_count': False},
            {'already_recorded': True}, {'source_binding': {}}, {'source_binding_receipt': {}},
            {'chunks': []}, {'chunks': [{'recorded_at': 10}]}, {'chunks': [{}]},
        ]
        receipts = []
        for change in changes:
            receipt = copy.deepcopy(self.receipt)
            receipt['data'].update(change)
            receipts.append(receipt)
        for key in ('source_binding', 'source_binding_receipt'):
            receipt = copy.deepcopy(self.receipt)
            del receipt['data'][key]
            receipts.append(receipt)
        receipts.extend([{'event': 'wrong', 'data': self.receipt['data']},
                         {'event': 'migration_import_prepared', 'data': None}])
        for receipt in receipts:
            with self.subTest(receipt=receipt):
                result, calls, failures, marker = self.invoke(receipt=receipt)
                self.assertEqual(result, 1)
                self.assertEqual(len(calls), 1)
                self.assertIn('new Open unbound package with zero recorded chunks', failures[0])
                self.assertIsNone(marker)

    def test_native_failure_is_preserved_without_interruption_marker(self):
        result, calls, failures, marker = self.invoke(native_error=replay.ReplayError('real native refusal'))
        self.assertEqual(result, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(failures, ['real native refusal'])
        self.assertIsNone(marker)

    def test_existing_partial_stage_retains_complete_selection_and_one_chunk_receipt(self):
        selection = {'chunks': [{'index': 0, 'approvals': ['a', 'b']},
                                {'index': 1, 'approvals': ['c', 'd']}]}
        path = self.directory / 'selection.json'
        original = json.dumps(selection).encode()
        path.write_bytes(original)
        command = ('migrate', 'import', '--action', 'stage', '--package', 'D:package', '--intent', path)
        receipt = {'event': 'migration_import_staged', 'data': {'chunk_index': 0, 'already_recorded': False}}
        result, calls, failures, marker = self.invoke('partial-stage', command=command, receipt=receipt)
        self.assertEqual(result, 1)
        self.assertEqual(calls, [(('migrate', 'import', '--action', 'stage', '--package', 'D:package',
                                  '--chunk', '0', '--approval', 'a', '--approval', 'b'), {})])
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(marker['saved_complete_selection_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(marker['selected_chunk_count'], 2)
        self.assertEqual(marker['native_receipt'], receipt)
        self.assertIn('intentional native interruption: partial-stage', failures[0])

    def test_existing_finalization_boundary_retains_completed_receipt_and_stdin_hash(self):
        command = ('migrate', 'finalize', '--plan', 'plan-digest')
        options = {'input_text': 'exact finalize intent\n'}
        receipt = {'event': 'migration_finalized', 'data': {'to': 'Finalized', 'already_recorded': False}}
        result, calls, failures, marker = self.invoke('after-finalize', command=command,
                                                    receipt=receipt, kwargs=options)
        self.assertEqual(result, 1)
        self.assertEqual(calls, [(command, options)])
        self.assertEqual(marker['native_receipt'], receipt)
        self.assertEqual(marker['stdin_sha256'], hashlib.sha256(options['input_text'].encode()).hexdigest())
        self.assertIn('intentional native interruption: after-finalize', failures[0])

    def test_unreached_boundary_cannot_return_success(self):
        result, calls, failures, marker = self.invoke(command=('book', 'info'),
                                                    receipt={'event': 'book_info', 'data': {}})
        self.assertEqual(result, 2)
        self.assertEqual(calls, [(('book', 'info'), {})])
        self.assertEqual(failures, [])
        self.assertIsNone(marker)

    def test_existing_marker_is_preserved_before_driver_load(self):
        self.marker.write_text('retained earlier attempt', encoding='utf-8')
        with mock.patch.object(interrupt.importlib.util, 'spec_from_file_location') as load, \
                redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            interrupt.main(['--driver', str(self.driver_path), '--boundary', 'after-package-before-bind',
                            '--marker', str(self.marker), '--', 'run'])
        self.assertEqual(raised.exception.code, 2)
        load.assert_not_called()
        self.assertEqual(self.marker.read_text(), 'retained earlier attempt')


if __name__ == '__main__':
    unittest.main()
