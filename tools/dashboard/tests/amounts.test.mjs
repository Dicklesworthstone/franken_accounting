import test from 'node:test';
import assert from 'node:assert/strict';
import {parseAmount, add, subtract, negate, compare, sum, format, ratio, csvCell, nativeRows, categoryNet} from '../web/amounts.mjs';

const amount = parseAmount;
test('a cent beyond the JavaScript integer precision boundary survives', () => {
  const a = amount('90071992547409.93 USD');
  assert.equal(a.n, 9007199254740993n);
  assert.equal(format(a, true), '90,071,992,547,409.93 USD');
  assert.equal(format(subtract(a, amount('90071992547409.92 USD'))), '0.01');
});
test('full signed i128 values remain exact', () => {
  assert.equal(amount('-170141183460469231731687303715884105728 X').n, -(2n ** 127n));
  assert.equal(amount('170141183460469231731687303715884105727 X').n, 2n ** 127n - 1n);
});
test('18-place units retain their smallest denomination', () => {
  const wei = amount('0.000000000000000001 ETH');
  assert.equal(wei.n, 1n);
  assert.equal(format(add(wei, amount('1.000000000000000000 ETH')), true), '1.000000000000000001 ETH');
});
test('scale alignment never rounds, and negative zero is normalized', () => {
  assert.equal(format(add(amount('1.2 USD'), amount('0.003 USD'))), '1.203');
  assert.equal(format(amount('-0.00 USD')), '0.00');
  assert.equal(format(negate(amount('1.00 USD'))), '−1.00');
});
test('different native units are never added or charted together', () => {
  assert.throws(() => add(amount('1 USD'), amount('1 EUR')), /different native units/);
  assert.throws(() => ratio(amount('1 USD'), amount('1 EUR')), /units differ/);
  assert.equal(format(sum(['1.00 USD', '999.00 EUR', '0.01 USD'], 'USD'), true), '1.01 USD');
});
test('ordering compares exact values, not decimal text or floats', () => {
  const values = ['90071992547409.93 USD', '-0.01 USD', '90071992547409.92 USD', '0.001 USD'];
  assert.deepEqual(values.map(amount).sort(compare).map(a => a.n), [-1n, 1n, 9007199254740992n, 9007199254740993n]);
});
test('only bounded normalized geometry is converted to Number', () => {
  const a = amount('99999999999999999999999999999999999999.99 USD');
  assert.equal(ratio(a, a, 240), 240);
  assert.equal(ratio(amount('1 USD'), amount('0 USD')), 0);
  assert.equal(ratio(amount('-2 USD'), amount('4 USD'), 200), 100);
  assert.equal(ratio(amount('10 USD'), amount('4 USD'), 200), 200);
  assert.equal(ratio(amount('0.0001 USD'), amount('1 USD')), .01);
});
test('malformed, exponent, comma, and nonfinite amounts are refused', () => {
  for (const text of ['1e3 USD', 'NaN USD', 'Infinity USD', '1,000.00 USD', '1. USD', '1 USD extra', '1', '+1 USD']) {
    assert.throws(() => amount(text), /Invalid native amount/, text);
  }
});
test('CSV cells quote delimiters and neutralize formula-leading text', () => {
  assert.equal(csvCell('A,"B"'), '"A,""B"""');
  for (const text of ['=1+1', '+cmd', '-1.00 USD', '@SUM(A1)', ' \t=1', '\r=1']) {
    assert.equal(csvCell(text), '"\'' + text.replaceAll('"', '""') + '"');
  }
  assert.equal(csvCell('90071992547409.93 USD'), '"90071992547409.93 USD"');
});
test('category cards use explicit sign and type rather than guessing from codes', () => {
  const rows = [{type:'Asset', debits:'11.00 USD', credits:'1.00 USD'},
    {type:'Liability', debits:'2.00 USD', credits:'7.00 USD'},
    {type:'Asset', debits:'500.00 EUR', credits:'0.00 EUR'}];
  assert.equal(nativeRows({rows}, 'USD').length, 2);
  assert.equal(format(categoryNet(rows, 'Asset', 'USD')), '10.00');
  assert.equal(format(categoryNet(rows, 'Liability', 'USD', true)), '5.00');
});
