// Independent presentation fixtures. These do not assert native accounting laws.
import test from 'node:test';
import assert from 'node:assert/strict';
import {sequence, snapshot, stockRows, comparisonModel, comparisonCsv, accountGraph, entryGraph} from '../web/workbench-model.mjs';
import {layoutGraph, graphBounds} from '../web/graph-layout.mjs';

const BOOK='b'.repeat(32),ACCOUNT='a'.repeat(32),ENTRY='1'.repeat(32),OTHER='2'.repeat(32),DOC='d'.repeat(64),COMMIT='c'.repeat(64);
const row=(code,d='10.00 USD',c='0.00 USD',extra={})=>({code,name:'Account '+code,type:'Asset',debits:d,credits:c,net:d,debits_pending:'0.00 USD',credits_pending:'0.00 USD',...extra});
const event=(at,data)=>({book:BOOK,coordinate:{branch:'trunk',known_at:at},data:{known_at:at,...data}});
const stock=(at,rows)=>event(at,{rows,periods:['P'],activity:false,mode:'stock',balanced:true,effective_through:'2026-09-30'});
const comparison=(left,right)=>({scope:'native-stock-snapshot-comparison',before:left,after:right,before_known_at:left.coordinate.known_at,after_known_at:right.coordinate.known_at});
const selection={period:'P',before:'7',after:'8'};
const model=(a,b)=>comparisonModel(comparison(stock('7',a),stock('8',b)),selection,'USD');
const contribution=(entry=ENTRY,extra={})=>({entry,entry_digest:'e'.repeat(64),class:'Original',recorded_at:'6',column:'posted',ordinal:'0',side:'Debit',amount:'10.00 USD',evidence:[{document_oid:DOC,doc_commit:COMMIT,role:'1'}],...extra});
const explanation=contributions=>event('8',{account:'1000',account_vid:ACCOUNT,name:'Cash',period:'P',contributions});
const entryResult=()=>({entry:event('9',{vid:ENTRY,entry_digest:'e'.repeat(64),class:'Pending',recorded_at:'6',principal:OTHER,
    legs:[{account_vid:ACCOUNT,account:'1000',account_name:'Cash',side:'Debit',amount:'10.00 USD',ordinal:'0'}],supersedes:[],superseded_by:[]}),
  evidence:event('10',{entry:ENTRY,entry_digest:'e'.repeat(64),documents:[{document_oid:DOC,doc_commit:COMMIT,kind:'Invoice',grade:'AgentUpload',role:'1'}]})});

test('recorded time is exact at the u64 limit and rejects lossy inputs',()=>{
  assert.equal(sequence('18446744073709551615'),2n**64n-1n);
  for(const n of ['18446744073709551616','01','-1','1.0','HEAD',1,true])assert.throws(()=>sequence(n));
  assert.equal(snapshot(event('18446744073709551615',{})),'18446744073709551615');
});
test('snapshot data cannot disagree with its envelope or selected book branch',()=>{
  assert.throws(()=>snapshot(event('8',{known_at:'7'})));
  assert.throws(()=>snapshot({...event('8',{}),coordinate:{branch:'draft',known_at:'8'}}));
  assert.throws(()=>snapshot({...event('8',{}),book:'invalid'}));
  assert.throws(()=>snapshot(event('8',{}),'7'));
});
test('stock gross columns reject duplicate cells, negative values and cross-unit mixtures',()=>{
  for(const rows of [[row('1000'),row('1000')],[row('1000','-1.00 USD')],[row('1000','1.00 USD','1.00 EUR')]])assert.throws(()=>stockRows(stock('8',rows)));
  assert.equal(stockRows(stock('8',[row('1000')]))[0].balance.n,1000n);
});
test('a one-cent comparison beyond 2^53 survives exactly',()=>{
  const result=model([row('1000','90071992547409.92 USD')],[row('1000','90071992547409.93 USD')]);
  assert.equal(result.rows[0].delta.n,1n);assert.equal(result.changed,1);
  assert.equal(result.rows[0].before.balance.n,9007199254740992n);
});
test('net-zero gross movement remains a change, not an unchanged balance',()=>{
  const r=model([row('1000','10.00 USD','2.00 USD')],[row('1000','15.00 USD','7.00 USD')]).rows[0];
  assert.equal(r.delta.n,0n);assert.equal(r.status,'changed');assert.equal(r.deltaColumns.debits.n,500n);assert.equal(r.deltaColumns.credits.n,500n);
});
test('pending-only and metadata-only differences are retained independently',()=>{
  const r=model([row('1000'),row('2000')],[row('1000','10.00 USD','0.00 USD',{debits_pending:'3.00 USD'}),row('2000','10.00 USD','0.00 USD',{name:'Historical rename'})]);
  assert.equal(r.rows[0].status,'changed');assert.equal(r.rows[0].delta.n,0n);
  assert.equal(r.rows[1].status,'metadata');assert.equal(r.rows[1].metadataChanged,true);assert.equal(r.changed,2);
});
test('absent zero rows differ from present zeros and no unit is silently converted',()=>{
  const r=model([row('1000','0.00 USD'),row('EUR','1.00 EUR','0.00 EUR',{net:'1.00 EUR',debits_pending:'0.00 EUR',credits_pending:'0.00 EUR'})],[row('2000','0.00 USD')]);
  assert.equal(r.rows.length,2);assert.equal(r.rows[0].status,'removed');assert.equal(r.rows[0].after,null);
  assert.equal(r.rows[1].status,'added');assert.equal(r.rows[1].before,null);assert.equal(r.changed,2);
});
test('comparison refuses every altered effective or recorded scope',()=>{
  const a=stock('7',[row('1000')]),b=stock('8',[row('1000')]);
  const attacks=[r=>r.after.book='a'.repeat(32),r=>r.after.data.activity=true,r=>r.after.data.periods=['Q'],
    r=>r.after.data.effective_through='2026-09-29',r=>r.after.data.mode='activity',r=>r.after_known_at='9',
    r=>r.after.coordinate.known_at='9',r=>r.scope='not-this-format'];
  for(const attack of attacks){const r=structuredClone(comparison(a,b));attack(r);assert.throws(()=>comparisonModel(r,selection,'USD'));}
});
test('native red verdict survives a numerically unchanged pair',()=>{
  const a=stock('7',[row('1000')]);a.data.balanced=false;
  const r=comparisonModel(comparison(a,stock('8',[row('1000')])),selection,'USD');
  assert.equal(r.balancedBefore,false);assert.equal(r.changed,0);
});
test('comparison export binds snapshots, unit, mode, row presence and exact difference',()=>{
  const r=model([], [row('=FORMULA','90071992547409.93 USD')]);
  const text=comparisonCsv(r,'demo');
  assert.match(text,/"before_present","after_present"/);
  assert.match(text,/"demo","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","P","2026-09-30","7","8"/);
  assert.match(text,/"'=FORMULA","USD","added","false","true"/);
  assert.match(text,/90,071,992,547,409.93 USD/);
});
test('account graph uses only returned entry and document references and deduplicates citations',()=>{
  const r=accountGraph(explanation([contribution(),contribution(ENTRY,{ordinal:'1'}),contribution(OTHER)]),'USD');
  assert.deepEqual(new Set(r.nodes.map(n=>n.id)),new Set(['account:'+ACCOUNT,'entry:'+ENTRY,'entry:'+OTHER,'document:'+DOC]));
  assert.equal(r.edges.filter(e=>e.relation==='cites').length,2);
  assert.equal(r.edges.filter(e=>e.relation==='posted').length,3);
  assert.equal(r.totalContributions,3);assert.equal(r.totalEntries,2);
});
test('graph preserves pending/released column semantics rather than claiming all legs posted',()=>{
  const r=accountGraph(explanation([contribution(ENTRY,{column:'pending'}),contribution(OTHER,{column:'released'})]),'USD');
  assert.deepEqual(new Set(r.edges.filter(e=>e.target.startsWith('account:')).map(e=>e.relation)),new Set(['pending','released']));
  const current=entryGraph(entryResult());
  assert.ok(current.edges.some(e=>e.relation==='leg account'));
  assert.ok(!current.edges.some(e=>e.relation==='posts to'));
});
test('bounded graph labels omitted entries without manufacturing summary objects',()=>{
  const r=accountGraph(explanation([contribution(),contribution(OTHER)]),'USD',1);
  assert.equal(r.totalEntries,2);assert.equal(r.omittedEntries,1);
  assert.ok(!r.nodes.some(n=>n.id==='entry:'+OTHER));
  assert.throws(()=>accountGraph(explanation([]),'USD',49));
});
test('conflicting entry digests or document commitments and future contributions refuse',()=>{
  assert.throws(()=>accountGraph(explanation([contribution(),contribution(ENTRY,{entry_digest:'f'.repeat(64)})]),'USD'),/conflicting payload/);
  assert.throws(()=>accountGraph(explanation([contribution(),contribution(OTHER,{evidence:[{document_oid:DOC,doc_commit:'f'.repeat(64),role:'1'}]})]),'USD'),/conflicting commitments/);
  assert.throws(()=>accountGraph(explanation([contribution(ENTRY,{recorded_at:'9'})]),'USD'),/beyond/);
});
test('entry graph retains separate current observations and rejects mismatched joins',()=>{
  const r=entryGraph(entryResult());assert.equal(r.knownAt,'9');assert.equal(r.evidenceAt,'10');assert.match(r.observed,/entry #9.*evidence #10/);
  const bad=entryResult();bad.evidence.data.entry=OTHER;assert.throws(()=>entryGraph(bad));
  const diff=entryResult();diff.evidence.data.entry_digest='a'.repeat(64);assert.throws(()=>entryGraph(diff));
});
test('force layout is deterministic and cannot mutate source references or amounts',()=>{
  const graph=accountGraph(explanation([contribution(),contribution(OTHER)]),'USD'),original=JSON.stringify(graph);
  const a=layoutGraph(graph),b=layoutGraph(graph);a.step(300);b.step(300);
  assert.deepEqual(a.nodes.map(n=>[n.x,n.y]),b.nodes.map(n=>[n.x,n.y]));
  assert.equal(JSON.stringify(graph),original);
  assert.equal(a.nodes.find(n=>n.root).x,0);assert.equal(a.nodes.find(n=>n.root).y,0);
  assert.ok(a.nodes.every(n=>Number.isFinite(n.x)&&Number.isFinite(n.y)));assert.equal(a.active,false);
});
test('layout bounds and endpoint checks reject malformed or excessive work',()=>{
  assert.throws(()=>layoutGraph({nodes:Array(221).fill({id:'n'}),edges:[]}));
  assert.throws(()=>layoutGraph({nodes:[{id:'a'}],edges:[{source:'a',target:'missing'}]}));
  const layout=layoutGraph({nodes:[{id:'a',root:true}],edges:[]});
  for(const n of [0,1001,1.5])assert.throws(()=>layout.step(n));
  layout.step(1);assert.deepEqual(graphBounds(layout.nodes),{x:-250,y:-170,width:500,height:340});
});
test('visual pinning remains stable when the simulation reheats',()=>{
  const graph=accountGraph(explanation([contribution(),contribution(OTHER)]),'USD'),layout=layoutGraph(graph);
  layout.step(250);const node=layout.nodes.find(n=>!n.root);node.x=900;node.y=-450;node.fixed=true;
  layout.reheat();layout.step(250);assert.equal(node.x,900);assert.equal(node.y,-450);
  assert.equal(node.detail.amount,'10.00 USD');
});
