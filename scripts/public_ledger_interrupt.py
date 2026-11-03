#!/usr/bin/env python3
"""Stop a real public-ledger run at a deterministic durable native boundary.

No native response is mocked. The partial-stage boundary submits the first
member of the already retained approved selection through the ordinary native
single-chunk command, then raises the driver's normal failure. The finalization
boundary raises only after a real new finalization has returned successfully.
These are controlled orchestration interruptions, not mid-transaction crashes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--boundary', choices=['partial-stage', 'after-finalize'], required=True)
    parser.add_argument('--marker', type=Path, required=True)
    parser.add_argument('driver_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    driver = args.driver.resolve(strict=True)
    if args.marker.exists() or not args.marker.parent.is_dir():
        parser.error('--marker must name a new file in an existing directory')
    driver_args = args.driver_args[1:] if args.driver_args[:1] == ['--'] else args.driver_args
    if not driver_args or driver_args[0] != 'run':
        parser.error('pass the original driver run arguments after --')
    sys.path.insert(0, str(driver.parent))
    spec = importlib.util.spec_from_file_location('public_ledger_controlled_run', driver)
    assert spec is not None and spec.loader is not None
    replay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(replay)
    ordinary = replay.Native.call
    interrupted = False

    def stop(native, requested, executed, event, extra=None):
        nonlocal interrupted
        marker = {
            'schema': 'fa-public-ledger-controlled-interruption-v1',
            'boundary': args.boundary,
            'scope': 'Controlled stop after a completed real native command; not a mid-transaction crash.',
            'driver_sha256': sha256(driver),
            'interruption_helper_sha256': sha256(Path(__file__)),
            'pins_sha256': sha256(native.output / 'recovery/pins.json'),
            'requested_arguments': list(map(str, requested)),
            'executed_arguments': list(map(str, executed)),
            'native_receipt': event,
            **(extra or {}),
        }
        with args.marker.open('x', encoding='utf-8') as stream:
            json.dump(marker, stream, indent=2, sort_keys=True)
            stream.write('\n')
        interrupted = True
        raise replay.ReplayError(f'intentional native interruption: {args.boundary}; receipt retained at {args.marker}')

    def injected(native, *command, **kwargs):
        words = list(map(str, command))
        if (args.boundary == 'partial-stage' and not interrupted
                and words[:4] == ['migrate', 'import', '--action', 'stage']
                and '--intent' in words):
            path = Path(words[words.index('--intent') + 1])
            original = path.read_bytes()
            selection = json.loads(original)
            replay.require(set(selection) == {'chunks'} and len(selection['chunks']) > 1,
                           'controlled partial-stage needs a retained group with multiple members')
            member = selection['chunks'][0]
            replay.require(set(member) == {'index', 'approvals'}
                           and type(member['index']) is int and member['index'] >= 0
                           and len(member['approvals']) == 2,
                           'invalid retained native selection')
            package = words[words.index('--package') + 1]
            actual = ['migrate', 'import', '--action', 'stage', '--package', package,
                      '--chunk', str(member['index'])]
            for approval in member['approvals']:
                actual += ['--approval', approval]
            event = ordinary(native, *actual, **kwargs)
            replay.require(event.get('event') == 'migration_import_staged'
                           and event['data']['chunk_index'] == member['index']
                           and event['data']['already_recorded'] is False,
                           'controlled partial-stage did not obtain a new native chunk receipt')
            replay.require(path.read_bytes() == original, 'retained complete selection changed')
            stop(native, command, actual, event, {
                'saved_complete_selection': str(path),
                'saved_complete_selection_sha256': hashlib.sha256(original).hexdigest(),
                'selected_chunk_count': len(selection['chunks']),
            })
        event = ordinary(native, *command, **kwargs)
        if (args.boundary == 'after-finalize' and not interrupted
                and words[:2] == ['migrate', 'finalize'] and '--plan' in words
                and event.get('data', {}).get('to') == 'Finalized'
                and event['data'].get('already_recorded') is False):
            submitted = kwargs.get('input_text', '').encode('utf-8')
            stop(native, command, command, event, {
                'stdin_sha256': hashlib.sha256(submitted).hexdigest(),
                'stdin_bytes': len(submitted),
            })
        return event

    replay.Native.call = injected
    try:
        code = replay.main(driver_args)
    finally:
        replay.Native.call = ordinary
    if not interrupted:
        print('The requested controlled interruption boundary was not reached.', file=sys.stderr)
        return code or 2
    if code != 1:
        print(f'Controlled interruption returned unexpected driver exit {code}.', file=sys.stderr)
        return 2
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
