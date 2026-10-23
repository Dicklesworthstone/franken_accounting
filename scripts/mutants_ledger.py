#!/usr/bin/env python3
"""Apply, restore, or plan one registries/mutants.toml row (helper for
scripts/mutants_execute.sh).

usage: mutants_ledger.py <root> ids
       mutants_ledger.py <root> file <MUT-id>
       mutants_ledger.py <root> tests <MUT-id>
       mutants_ledger.py <root> apply <MUT-id> <saved-copy>
       mutants_ledger.py <root> restore <MUT-id> <saved-copy>

ids      every mutant id, in ledger order;
file     the workspace-relative file the mutant edits;
tests    one line per killed_by entry: the cargo test arguments that run
         exactly that test, tab-separated;
apply    checks `find` occurs exactly once in `file`, saves the file's bytes
         to <saved-copy>, and writes the mutated file;
restore  writes <saved-copy> back over `file`.
"""
import os
import sys
import tomllib


def ledger(root):
    with open(os.path.join(root, "registries/mutants.toml"), "rb") as fh:
        return tomllib.load(fh)["mutant"]


def row(root, mid):
    rows = [m for m in ledger(root) if m["id"] == mid]
    if len(rows) != 1:
        sys.exit(f"mutants_ledger: {mid}: {len(rows)} rows")
    return rows[0]


def cargo_args(mid, entry):
    """`crate::lib::mod::tests::name` or `crate::tests/file.rs::name`."""
    crate, rest = entry.split("::", 1)
    if rest.startswith("tests/"):
        target, name = rest.split("::", 1)
        target = target.removeprefix("tests/").removesuffix(".rs")
        return ["-p", crate, "--test", target, "--", "--exact", name]
    if rest.startswith("lib::"):
        return ["-p", crate, "--lib", "--", "--exact", rest.removeprefix("lib::")]
    sys.exit(f"mutants_ledger: {mid}: unrecognised killed_by `{entry}`")


def main(argv):
    root, mode, *rest = argv
    if mode == "ids":
        print("\n".join(m["id"] for m in ledger(root)))
    elif mode == "file":
        (mid,) = rest
        print(row(root, mid)["file"])
    elif mode == "tests":
        (mid,) = rest
        for entry in row(root, mid)["killed_by"]:
            print("\t".join(cargo_args(mid, entry)))
    elif mode in ("apply", "restore"):
        mid, saved = rest
        m = row(root, mid)
        path = os.path.join(root, m["file"])
        if mode == "apply":
            with open(path, encoding="utf-8") as fh:
                original = fh.read()
            count = original.count(m["find"])
            if count != 1:
                sys.exit(f"mutants_ledger: {mid}: `find` occurs {count} times in {m['file']}")
            with open(saved, "w", encoding="utf-8") as fh:
                fh.write(original)
            mutated = original.replace(m["find"], m["replace"])
        else:
            with open(saved, encoding="utf-8") as fh:
                mutated = fh.read()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(mutated)
    else:
        sys.exit(f"mutants_ledger: unknown mode `{mode}`")


if __name__ == "__main__":
    main(sys.argv[1:])
