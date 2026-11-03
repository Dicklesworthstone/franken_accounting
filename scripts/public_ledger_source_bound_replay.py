"""Run the complete public-ledger driver with native source binding enabled.

This fresh-run entry point delegates to the canonical driver's --bind-source
mode, which durably pins the requested source binding before native work.
Fresh outputs remain mandatory here; use public_ledger.py run --resume for
an interrupted, originally bound canonical run.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, add_help=False, allow_abbrev=False)
    parser.add_argument('--repo', required=True, type=Path)
    selected, arguments = parser.parse_known_args()
    # The stock parser accepts unique long-option prefixes. Refuse every
    # spelling it can interpret as --resume before resolving the repository,
    # importing the driver or allowing it to inspect an existing output.
    options = [argument.partition('=')[0] for argument in arguments]
    resuming = any(option.startswith('--') and len(option) > 2
                   and '--resume'.startswith(option) for option in options)
    if not arguments or arguments[0] != 'run' or resuming:
        parser.error('forward a fresh public_ledger.py run invocation; --resume is not supported here')
    if any(option.startswith('--') and len(option) > 2
           and '--no-bind-source'.startswith(option) for option in options):
        parser.error('this entry point requires --bind-source; --no-bind-source is not supported here')
    sys.path.insert(0, str(selected.repo.resolve(strict=True) / 'scripts'))
    import public_ledger

    return public_ledger.main([arguments[0], '--bind-source', *arguments[1:]])


if __name__ == '__main__':
    raise SystemExit(main())
