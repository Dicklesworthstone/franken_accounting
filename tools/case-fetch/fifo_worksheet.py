"""Gross movements in a commingled-account FIFO worksheet (pdftotext -layout).

The two source-attribution columns for withdrawals are added. The terminal
source balances and the court's reported FIFO result are never inputs.
"""
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta


COLUMNS = re.compile(r"Account Balance|Deposit:|Withdrawal:|Resulting balance:")
COLUMN_NAMES = ["Account Balance", "Deposit:", "Deposit:", "Withdrawal:",
                "Withdrawal:", "Resulting balance:", "Resulting balance:"]
AMOUNT = re.compile(r"(?<![\d.])\$?([\d,]+)\.(\d{2})(?!\d)")
DATE = re.compile(r"(?<!\d)\d{1,2}/\d{1,2}/\d{2}(?!\d)")

@dataclass
class Statement:
    opening: date
    closing: date | None = None
    rows: list = field(default_factory=list)


def day(text):
    return datetime.strptime(text, "%m/%d/%y").date()


def dollars_in_row(line, ends):
    cells = {}
    for match in AMOUNT.finditer(line):
        if match.end() < ends[0] - 5:
            # A parenthetical balance in the annotation to the trustee's alternative.
            continue
        column = min(range(len(ends)), key=lambda c: abs(ends[c] - match.end()))
        if column >= 5:
            continue
        if (abs(ends[column] - match.end()) > 3 or column in cells
                or line[:match.start()].endswith(("-", "("))
                or not re.fullmatch(r"(?:\d+|\d{1,3}(?:,\d{3})+)", match[1])):
            raise ValueError(f"ambiguous amount under worksheet header: {line.strip()}")
        cells[column] = int(match[1].replace(",", "")) * 100 + int(match[2])
    return cells


def table_rows(pages):
    """Return date, monetary cells, and alternative-debit interpretation in source order."""
    for page in pages:
        lines = iter(page.splitlines())
        printed_lines = page.splitlines()
        header_at = next((i for i, l in enumerate(printed_lines) if "Account Balance" in l), None)
        if header_at is None or header_at + 1 >= len(printed_lines):
            raise ValueError("missing worksheet column labels")
        header = printed_lines[header_at]
        headers = list(COLUMNS.finditer(header))
        if [h.group() for h in headers] != COLUMN_NAMES:
            raise ValueError("worksheet page lacks its seven printed monetary columns")
        if printed_lines[header_at+1].split() != ["Social", "Security", "Other"] * 3:
            raise ValueError("worksheet source-column classifications changed")
        ends = [h.end() for h in headers]
        for line in lines:
            left = line[:22].strip()
            match = DATE.search(left)
            variant = None
            if "thru" in left and match:
                last = next((l for l in lines if l.strip()), "")
                end = DATE.search(last[:22])
                if not end or day(end.group()) < day(match.group()):
                    raise ValueError(f"invalid printed movement range: {left}")
                printed = f"{day(match.group()):%m/%d/%y}–{day(end.group()):%m/%d/%y}"
                cells = dollars_in_row(line, ends)
                next_cells = dollars_in_row(last, ends)
                if set(cells) & set(next_cells):
                    raise ValueError("one movement has repeated monetary columns")
                cells.update(next_cells)
            else:
                if left.startswith("before") and match:
                    printed, variant = "unknown, before petition", ("schedule-debit", day(match.group()))
                elif left.startswith("($"):
                    if "balance T/ee says" not in page:
                        raise ValueError("alternative petition balance lacks its trustee attribution")
                    printed, variant = "unknown, before petition", ("trustee-debit", None)
                elif left.startswith("unknown"):
                    printed = "unknown"
                elif match and not left[:match.start()].strip():
                    printed = day(match.group()).strftime("%m/%d/%y")
                else:
                    continue
                cells = dollars_in_row(line, ends)
            if cells:
                has_source_balances = any(m.end() > ends[4] + 5 for m in AMOUNT.finditer(line))
                yield printed, cells, variant, has_source_balances


def movements(text, anchor):
    """Recover the four TSV columns from one independently anchored appendix."""
    match = re.fullmatch(r"(Appendix [1-9]\d*)\|p([1-9]\d*)-([1-9]\d*)", anchor)
    if not match:
        raise ValueError("worksheet anchor must name the appendix and its physical page range")
    title, first, last = match[1], int(match[2]), int(match[3])
    pages = text.split("\f")
    cover = "OPINION " + title.upper()
    if not (1 < first <= last <= len(pages)) or [
        i for i, page in enumerate(pages)
        if cover in [line.strip() for line in page.splitlines()]
    ] != [first - 2]:
        raise ValueError(f"no unique matching appendix cover before {anchor}")

    # Each repeated balance opens a statement. After any explicit close the
    # following balance opens the next statement, even if the amounts differ.
    groups = []
    opening = None
    endpoint = None
    for printed, cells, variant, has_source_balances in table_rows(pages[first - 1:last]):
        if 0 in cells:
            on = day(printed)
            if not groups:
                opening = (on.isoformat(), printed, "opening", cells[0])
            if has_source_balances:
                if groups and on <= groups[-1].opening:
                    raise ValueError("worksheet opening dates are out of order")
                groups.append(Statement(on))
            else:
                if not groups or groups[-1].closing or on < groups[-1].opening:
                    raise ValueError("closing balance without an open worksheet statement")
                groups[-1].closing = on
            continue
        if not groups or groups[-1].closing:
            raise ValueError("movement outside an open worksheet statement")
        rows = groups[-1].rows
        for column, kind in ((1, "social"), (2, "other")):
            if column in cells:
                rows.append((printed, kind, cells[column]))
        if 3 in cells or 4 in cells:
            kind = "debit"
            if variant:
                kind, cutoff = variant
                if cutoff:
                    if endpoint is not None:
                        raise ValueError("multiple petition cutoffs in worksheet")
                    endpoint = cutoff
                elif endpoint is None:
                    raise ValueError("trustee alternative precedes the petition cutoff")
            rows.append((printed, kind, cells.get(3, 0) + cells.get(4, 0)))
    if not opening or not endpoint or [r[1] for r in groups[-1].rows[-2:]] != [
        "schedule-debit", "trustee-debit"
    ]:
        raise ValueError("worksheet lacks its opening or both petition alternatives")

    output = [opening]
    for i, group in enumerate(groups):
        rows = group.rows
        if not rows:
            raise ValueError("empty worksheet statement")
        cutoff = group.closing
        if not cutoff and i + 1 < len(groups):
            # Where the final dated activity directly precedes the next
            # opening it fixes the cutoff. Otherwise use the next printed
            # closing observation and retain the original printed dates.
            printed = rows[-1][0].split("–")[-1]
            if DATE.fullmatch(printed) and day(printed) + timedelta(days=1) == groups[i + 1].opening:
                cutoff = day(printed)
            else:
                cutoff = next((g.closing for g in groups[i + 1:] if g.closing), endpoint)
        cutoff = cutoff or endpoint
        if not groups[0].opening <= group.opening <= cutoff <= endpoint:
            raise ValueError("worksheet statement falls outside the observed interval")
        for printed, kind, cents in rows:
            # A source can print an earlier date in a later statement. Preserve
            # it verbatim while requiring it to lie within the observed history.
            if any(not groups[0].opening <= day(d) <= cutoff for d in DATE.findall(printed)):
                raise ValueError("printed movement date is outside the observed interval")
            output.append((cutoff.isoformat(), printed, kind, cents))
    return output


def verify(text, anchor, scope, data):
    rows = movements(text, anchor)
    expected_scope = re.fullmatch(r"scheme:.+-(\d{4}-\d{2})-(\d{4}-\d{2})", scope)
    if not expected_scope or expected_scope.groups() != (rows[0][0][:7], rows[-1][0][:7]):
        raise ValueError("worksheet movements do not span the declared scope")
    supplied = [line for line in data.decode("utf-8").splitlines() if not line.startswith("#")]
    expected = ["\t".join([observed, printed, kind, str(cents)])
                for observed, printed, kind, cents in rows]
    if supplied != expected:
        at = next((i for i, (a, b) in enumerate(zip(supplied, expected)) if a != b),
                  min(len(supplied), len(expected)))
        raise ValueError(f"worksheet movement {at+1} differs in date, class, amount, or order "
                         f"({len(expected)} source rows, {len(supplied)} supplied)")
    return len(rows)
