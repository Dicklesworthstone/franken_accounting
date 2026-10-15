// Money and commit sequences never pass through Number. Only final normalized
// chart coordinates do; displayed/exported values remain exact decimal strings.
export function parseAmount(value) {
  const match = /^(-?)(\d+)(?:\.(\d+))? ([^\s]+)$/.exec(value);
  if (!match || value.length > 512) throw new Error(`Invalid native amount: ${String(value).slice(0, 80)}`);
  const scale = (match[3] || '').length;
  return { n: BigInt(match[1] + match[2] + (match[3] || '')), scale, unit: match[4] };
}
export const zero = (unit, scale = 2) => ({ n: 0n, scale, unit });
export function add(a, b) {
  if (a.unit !== b.unit) throw new Error('Amounts in different native units cannot be combined.');
  const scale = Math.max(a.scale, b.scale);
  return { n: a.n * 10n ** BigInt(scale - a.scale) + b.n * 10n ** BigInt(scale - b.scale), scale, unit: a.unit };
}
export const negate = a => ({ ...a, n: -a.n });
export const subtract = (a, b) => add(a, negate(b));
export function compare(a, b) {
  const difference = subtract(a, b).n;
  return difference < 0n ? -1 : difference > 0n ? 1 : 0;
}
export function sum(values, unit) {
  const selected = values.map(parseAmount).filter(a => a.unit === unit);
  return selected.reduce(add, zero(unit, selected[0]?.scale ?? 2));
}
export function format(a, withUnit = false) {
  let digits = (a.n < 0n ? -a.n : a.n).toString().padStart(a.scale + 1, '0');
  const whole = (a.scale ? digits.slice(0, -a.scale) : digits).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return (a.n < 0n ? '−' : '') + whole + (a.scale ? '.' + digits.slice(-a.scale) : '') + (withUnit ? ` ${a.unit}` : '');
}
export function ratio(value, maximum, pixels = 100) {
  if (value.unit !== maximum.unit) throw new Error('Chart units differ.');
  const scale = Math.max(value.scale, maximum.scale);
  const n = (value.n < 0n ? -value.n : value.n) * 10n ** BigInt(scale - value.scale);
  const d = (maximum.n < 0n ? -maximum.n : maximum.n) * 10n ** BigInt(scale - maximum.scale);
  if (!d) return 0;
  // At most one ten-thousandth of the chart width is discarded, never money.
  return Number((n > d ? d : n) * 10000n / d) / 10000 * pixels;
}
export function csvCell(value) {
  let text = String(value);
  if (/^[\s]*[=+\-@\t\r]/.test(text)) text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}
export function nativeRows(report, unit) {
  return report.rows.filter(row => parseAmount(row.debits).unit === unit);
}
export function categoryNet(rows, type, unit, creditNormal = false) {
  const selected = rows.filter(r => r.type.toLowerCase() === type.toLowerCase());
  const value = subtract(sum(selected.map(r => r.debits), unit), sum(selected.map(r => r.credits), unit));
  return creditNormal ? negate(value) : value;
}
