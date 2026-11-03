"""Run the complete public-ledger driver with native source binding enabled.

This focused acceptance harness leaves the imported driver and every assertion
unchanged. Its sole command transformation adds the existing --bind-source
switch to native import preparation, including the driver's exact retry.
Fresh outputs are mandatory; recovery behavior belongs to the stock driver.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--repo', required=True, type=Path)
    selected, arguments = parser.parse_known_args()
    if not arguments or arguments[0] != 'run' or '--resume' in arguments:
        parser.error('forward a fresh public_ledger.py run invocation; --resume is not supported here')
    sys.path.insert(0, str(selected.repo.resolve(strict=True) / 'scripts'))
    import public_ledger

    class SourceBoundNative(public_ledger.Native):
        def command(self, *args: object) -> list[str]:
            if args[:4] == ('migrate', 'import', '--action', 'prepare'):
                args = (*args, '--bind-source')
            return super().command(*args)

    public_ledger.Native = SourceBoundNative
    return public_ledger.main(arguments)


if __name__ == '__main__':
    raise SystemExit(main())
