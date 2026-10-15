import test from 'node:test';
import assert from 'node:assert/strict';
import {parseAmount} from '../web/amounts.mjs';
import {ledgerModel,agingModel,dayNumber,bandLabel,envelope,reportCsv,requestGate} from '../web/report-model.mjs';

const book='a'.repeat(32), digest='b'.repeat(64),seq='9007199254740993';
const selection={account:'1000',unit:'USD',from:'2026-09-01',to:'2026-09-30',known_at:seq};
function ledger(){
  return {book,coordinate:{branch:'trunk',known_at:seq},data:{known_at:seq,effective_from:selection.from,effective_through:selection.to,
    cells:[{account:'1000',name:'Exact balance',unit:'USD',opening:'90071992547409.93 USD',debits:'0.02 USD',credits:'0.03 USD',net_change:'-0.01 USD',closing:'90071992547409.92 USD',line_count:'2'}],
    lines:[{account:'1000',unit:'USD',effective_date:'2026-09-02',recorded_at:'9007199254740992',entry_digest:digest,leg_index:'0',class:'Original',reason_code:'None',debits:'0.02 USD',credits:'0.00 USD',running_balance:'90071992547409.95 USD'},
      {account:'1000',unit:'USD',effective_date:'2026-09-03',recorded_at:seq,entry_digest:'c'.repeat(64),leg_index:'1',class:'Reversal',reason_code:'WrongAmount',debits:'0.00 USD',credits:'0.03 USD',running_balance:'90071992547409.92 USD'}]}};
}
function aging(){
  const bands=[{lower_inclusive:'0',upper_inclusive:'30'},{lower_inclusive:'31',upper_inclusive:null}];
  const report={book,coordinate:{branch:'trunk',known_at:seq},data:{account:'1100',known_at:seq,effective_through:'2026-09-30',bands,
    cells:[{account:'1100',unit:'USD',bucket:'1',debits:'60.00 USD',credits:'0.00 USD',item_count:'1'}],
    items:[{entry:book,ordinal:'0',account:'1100',side:'Debit',effective_date:'2026-08-01',recorded_at:seq,original:'100.00 USD',applied:'30.00 USD',applied_out:'10.00 USD',open:'60.00 USD',age_days:'60',bucket:'1'}],
    totals:[{unit:'USD',debits:'60.00 USD',credits:'0.00 USD',item_count:'1'}]}};
  const reconciliation={book,coordinate:{branch:'trunk',known_at:seq},data:{account:'1100',known_at:seq,effective_through:'2026-09-30',bands:structuredClone(bands),reconciled:true,
    rows:[{unit:'USD',open_debits:'60.00 USD',open_credits:'0.00 USD',posted_net:'60.00 USD',open_net:'60.00 USD',difference:'0.00 USD'}]}};
  return {report,reconciliation};
}
test('ledger validates cents and recorded sequences beyond Number precision',()=>{
  const model=ledgerModel(ledger(),selection);
  assert.equal(model.closing.n,9007199254740992n);
  assert.equal(model.min.n,9007199254740992n);assert.equal(model.max.n,9007199254740995n);
  assert.equal(model.points[1].y,1);assert.equal(model.points[2].y,0);
  assert.equal(model.lines[1].recorded_at,seq);
});
test('ledger rejects forged running totals, counts, scope, units and out-of-prefix lines',()=>{
  for(const change of [r=>r.data.lines[0].running_balance='90071992547409.94 USD',r=>r.data.cells[0].closing='0.00 USD',
    r=>r.data.cells[0].line_count='1',r=>r.data.lines[0].unit='EUR',r=>r.data.lines[0].recorded_at='9007199254740994',
    r=>r.data.lines.reverse(),r=>r.data.known_at='1',r=>r.data.effective_from='2026-08-01']){
    const r=ledger();change(r);assert.throws(()=>ledgerModel(r,selection));
  }
});
test('missing ledger cell is absent rather than a zero; flat cells remain real',()=>{
  const r=ledger();r.data.cells=[];r.data.lines=[];assert.equal(ledgerModel(r,selection),null);
  const flat=ledger();flat.data.lines=[];Object.assign(flat.data.cells[0],{debits:'0.00 USD',credits:'0.00 USD',net_change:'0.00 USD',closing:flat.data.cells[0].opening,line_count:'0'});
  assert.ok(ledgerModel(flat,selection).points.every(p=>p.y===.5));
});
test('daily geometry preserves opening and closing while not claiming intraday extrema',()=>{
  const r=ledger();r.data.lines[1].effective_date='2026-09-02';const m=ledgerModel(r,selection);
  assert.equal(m.dayCount,1);assert.equal(m.points.length,3);assert.equal(m.points[1].amount.n,9007199254740992n);
});
test('bounded sampling keeps extrema, endpoints and chronological indices',()=>{
  const points=Array.from({length:3000},(_,i)=>({index:i,amount:parseAmount(`${i===725?999999:i===729?-999999:i} USD`)}));
  const result=envelope(points,100);
  assert.ok(result.length<=100);assert.equal(result[0],points[0]);assert.equal(result.at(-1),points.at(-1));
  assert.ok(result.includes(points[725]));assert.ok(result.includes(points[729]));
  assert.ok(result.every((p,i)=>i===0||p.index>result[i-1].index));
});
test('civil dates use UTC rather than machine timezone or a 1900-year offset',()=>{
  assert.equal(dayNumber('2024-03-01')-dayNumber('2024-02-28'),2);
  assert.equal(dayNumber('0099-01-02')-dayNumber('0099-01-01'),1);
  assert.throws(()=>dayNumber('2026-02-30'));assert.throws(()=>dayNumber('2026-9-1'));
});
test('aging preserves partial applications and validates real effective-date bands',()=>{
  const {report,reconciliation}=aging();const m=agingModel(report,reconciliation,'USD');
  assert.equal(m.debits.n,6000n);assert.equal(m.bands[0].count,0n);assert.equal(m.bands[1].count,1n);
  assert.equal(bandLabel(m.bands[0]),'0–30 days');assert.equal(bandLabel(m.bands[1]),'31+ days');
  assert.equal(m.items[0].applied,'30.00 USD');assert.equal(m.items[0].applied_out,'10.00 USD');
});
test('aging refuses omitted or corrupt items, bucket totals and application amounts',()=>{
  for(const change of [r=>r.items[0].open='61.00 USD',r=>r.items[0].bucket='0',r=>r.items[0].age_days='59',
    r=>r.cells[0].debits='59.00 USD',r=>r.totals=[],r=>r.items.push({...r.items[0]}),r=>r.items[0].recorded_at='9007199254740994']){
    const {report,reconciliation}=aging();change(report.data);assert.throws(()=>agingModel(report,reconciliation,'USD'));
  }
});
test('a red reconciliation remains red, but a green nonzero difference refuses',()=>{
  const {report,reconciliation}=aging();Object.assign(reconciliation.data.rows[0],{posted_net:'60.01 USD',difference:'0.01 USD'});
  assert.throws(()=>agingModel(report,reconciliation,'USD'));
  reconciliation.data.reconciled=false;const m=agingModel(report,reconciliation,'USD');assert.equal(m.reconciled,false);assert.equal(m.check.difference,'0.01 USD');
});
test('aging requires the same book, snapshot and cutoff on both native reads',()=>{
  for(const change of [r=>r.book='c'.repeat(32),r=>r.data.known_at='1',r=>r.coordinate.known_at='1',r=>r.data.effective_through='2026-10-01']){
    const {report,reconciliation}=aging();change(reconciliation);assert.throws(()=>agingModel(report,reconciliation,'USD'));
  }
});
test('unreported units have no reconciliation claim and are never converted',()=>{
  const {report,reconciliation}=aging();const m=agingModel(report,reconciliation,'EUR');assert.equal(m.items.length,0);assert.equal(m.check,null);assert.equal(m.debits.unit,'EUR');
});
test('exports bind original scope and exact strings, escaping hostile cells',()=>{
  const r=ledger();r.data.lines[0].reason_code='=HYPERLINK("https://bad")';
  const csv=reportCsv('demo',book,'ledger',r.data,'USD',[r.data.lines[0]]);
  assert.ok(csv.includes('"demo"'));assert.ok(csv.includes(seq));assert.ok(csv.includes('90071992547409.95 USD'));
  assert.ok(csv.includes('"\'=HYPERLINK(""https://bad"")"'));assert.equal(csv.trim().split('\r\n').length,2);
});
test('invalidating the request gate prevents late success from restoring old results',async()=>{
  const gate=requestGate();const old=gate.ticket();gate.invalidate();assert.equal(old(),false);
  const current=gate.ticket();await Promise.resolve();assert.equal(current(),true);
  const newer=gate.ticket();assert.equal(current(),false);assert.equal(newer(),true);
});
