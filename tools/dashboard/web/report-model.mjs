// Presentation checks, selectors and bounded geometry. Not a journal fold or proof.
import {parseAmount, add, subtract, compare, zero, ratio, csvCell} from './amounts.mjs';

export const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const uint = value => { requireThat(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value), 'Missing exact integer in report.'); return BigInt(value); };
const eq = (a,b) => compare(a,b) === 0;
const money = (value,unit) => { const a=parseAmount(value); requireThat(a.unit===unit,'Mixed units in native report.'); return a; };
const positive = (value,unit) => { const a=money(value,unit); requireThat(a.n>=0n,'A debit/credit/open amount is negative.'); return a; };
export function dayNumber(value) {
  requireThat(typeof value==='string' && /^\d{4}-\d{2}-\d{2}$/.test(value),'Expected an explicit civil date.');
  const ms=Date.parse(value+'T00:00:00Z');
  requireThat(Number.isFinite(ms) && new Date(ms).toISOString().slice(0,10)===value,'Invalid civil date.');
  return ms/86400000; // Geometry only, never amount arithmetic or recorded time.
}
export function bandLabel(band) {
  return band.upper_inclusive===null ? `${band.lower_inclusive}+ days` :
    band.lower_inclusive===band.upper_inclusive ? `${band.lower_inclusive} days` : `${band.lower_inclusive}–${band.upper_inclusive} days`;
}
export function envelope(points, limit=240) {
  requireThat(Number.isInteger(limit)&&limit>=6,'Chart point bound must be at least six.');
  if(points.length<=limit)return points;
  const out=[points[0]],size=Math.ceil((points.length-2)/Math.floor((limit-2)/4));
  for(let start=1;start<points.length-1;start+=size){
    const end=Math.min(points.length-1,start+size);let low=start,high=start;
    for(let i=start+1;i<end;i++){
      if(compare(points[i].amount,points[low].amount)<0)low=i;
      if(compare(points[i].amount,points[high].amount)>0)high=i;
    }
    for(const i of [...new Set([start,low,high,end-1])].sort((a,b)=>a-b))out.push(points[i]);
  }
  out.push(points.at(-1));return out;
}
export function ledgerModel(report, selection) {
  const b=report.data,unit=selection.unit;
  requireThat(report.coordinate?.branch==='trunk' && b.known_at===report.coordinate.known_at,'Ledger coordinate mismatch.');
  requireThat(selection.known_at==='HEAD'||b.known_at===selection.known_at,'Ledger snapshot differs from selection.');
  requireThat(b.effective_from===selection.from&&b.effective_through===selection.to,'Ledger effective range differs from selection.');
  requireThat(Array.isArray(b.cells)&&b.cells.length<=1&&Array.isArray(b.lines),'Malformed ledger report.');
  if(!b.cells.length){requireThat(!b.lines.length,'Movement rows without an account cell.');return null;}
  const cell=b.cells[0];
  requireThat(cell.account===selection.account&&cell.unit===unit,'Ledger cell differs from selection.');
  requireThat(uint(cell.line_count)===BigInt(b.lines.length),'Ledger movement count mismatch.');
  const opening=money(cell.opening,unit),closing=money(cell.closing,unit),days=new Map();
  let running=opening,debits=zero(unit,opening.scale),credits=zero(unit,opening.scale),lastDate=selection.from;
  let previous=null;const identities=new Set();
  for(const line of b.lines){
    requireThat(line.account===cell.account&&line.unit===unit,'Foreign ledger line.');
    requireThat(line.effective_date>=lastDate&&line.effective_date<=selection.to,'Ledger movements not in effective-date order.');
    dayNumber(line.effective_date);
    const seq=uint(line.recorded_at),leg=uint(line.leg_index);
    requireThat(seq<=uint(b.known_at),'Movement beyond the selected recorded prefix.');
    requireThat(/^[a-f0-9]{64}$/.test(line.entry_digest),'Invalid entry digest.');
    if(previous&&previous.effective_date===line.effective_date){
      const pseq=uint(previous.recorded_at),pleg=uint(previous.leg_index);
      requireThat(seq>pseq||(seq===pseq&&(line.entry_digest>previous.entry_digest||
        (line.entry_digest===previous.entry_digest&&leg>pleg))),'Ledger tie ordering differs from the native contract.');
    }
    const identity=line.entry_digest+':'+line.leg_index;
    requireThat(!identities.has(identity),'Repeated ledger leg.');identities.add(identity);
    const d=positive(line.debits,unit),c=positive(line.credits,unit);
    running=add(running,subtract(d,c));debits=add(debits,d);credits=add(credits,c);
    requireThat(eq(running,money(line.running_balance,unit)),'Native movement and running balance disagree.');
    lastDate=line.effective_date;previous=line;
    days.set(line.effective_date,{date:line.effective_date,amount:money(line.running_balance,unit),label:'Daily closing balance'});
  }
  requireThat(eq(debits,money(cell.debits,unit))&&eq(credits,money(cell.credits,unit))&&
    eq(subtract(debits,credits),money(cell.net_change,unit))&&eq(running,closing),'Native opening, movement and closing totals disagree.');
  const points=[{date:selection.from,amount:opening,label:'Opening before selected movements'},...days.values(),
    {date:selection.to,amount:closing,label:'Closing through inclusive cutoff'}];
  let min=points[0].amount,max=min;
  for(const p of points){if(compare(p.amount,min)<0)min=p.amount;if(compare(p.amount,max)>0)max=p.amount;}
  const range=subtract(max,min),start=dayNumber(selection.from),span=dayNumber(selection.to)-start;
  const selected=envelope(points);
  return {cell,lines:b.lines,opening,closing,debits,credits,min,max,dayCount:days.size,sampled:selected.length<points.length,
    points:selected.map(p=>({...p,x:span?(dayNumber(p.date)-start)/span:0.5,
      y:range.n===0n?0.5:ratio(subtract(p.amount,min),range,1)}))};
}
export function agingModel(report,reconciliation,unit) {
  const b=report.data,r=reconciliation.data;
  requireThat(report.book===reconciliation.book&&report.coordinate?.branch==='trunk'&&reconciliation.coordinate?.branch==='trunk'&&
    b.known_at===report.coordinate.known_at&&r.known_at===reconciliation.coordinate.known_at&&b.known_at===r.known_at&&
    b.account===r.account&&b.effective_through===r.effective_through,'Aging and reconciliation scopes differ.');
  requireThat(typeof r.reconciled==='boolean'&&Array.isArray(b.bands)&&b.bands.length>0&&b.bands.length<=13,'Malformed native aging verdict/bands.');
  requireThat(JSON.stringify(b.bands)===JSON.stringify(r.bands),'Reconciliation age bands differ.');
  let lower=0n;
  b.bands.forEach((band,i)=>{
    requireThat(uint(band.lower_inclusive)===lower,'Age bands are not contiguous.');
    if(i===b.bands.length-1)requireThat(band.upper_inclusive===null,'Last age band must be open-ended.');
    else{const upper=uint(band.upper_inclusive);requireThat(upper>=lower,'Invalid age band.');lower=upper+1n;}
  });
  const items=b.items.filter(i=>parseAmount(i.open).unit===unit),totals=b.totals.filter(t=>t.unit===unit),checks=r.rows.filter(row=>row.unit===unit);
  requireThat(totals.length<=1&&checks.length<=1,'Repeated native aging totals.');
  const scale=items.length?parseAmount(items[0].open).scale:checks.length?parseAmount(checks[0].difference).scale:2;
  const bands=b.bands.map((band,index)=>({...band,index,debits:zero(unit,scale),credits:zero(unit,scale),count:0n}));
  const nativeCells=b.cells.filter(c=>c.unit===unit),seen=new Set();
  for(const c of nativeCells){
    const bucket=uint(c.bucket);requireThat(bucket<BigInt(bands.length)&&c.account===b.account,'Invalid aging cell.');
    requireThat(!seen.has(c.bucket),'Duplicate aging cell.');seen.add(c.bucket);
    Object.assign(bands[Number(bucket)],{debits:positive(c.debits,unit),credits:positive(c.credits,unit),count:uint(c.item_count)});
  }
  const counted=bands.map(()=>({debits:zero(unit,scale),credits:zero(unit,scale),count:0n})),identities=new Set();
  for(const item of items){
    const bucket=uint(item.bucket),age=uint(item.age_days),ordinal=uint(item.ordinal);
    requireThat(bucket<BigInt(bands.length)&&item.account===b.account&&['Debit','Credit'].includes(item.side),'Invalid aged item.');
    requireThat(/^[a-f0-9]{32}$/.test(item.entry),'Invalid aged entry handle.');
    const id=item.entry+':'+ordinal;requireThat(!identities.has(id),'Repeated open item.');identities.add(id);
    requireThat(uint(item.recorded_at)<=uint(b.known_at),'Open item beyond selected prefix.');
    requireThat(BigInt(dayNumber(b.effective_through)-dayNumber(item.effective_date))===age,'Native effective-date age mismatch.');
    const band=bands[Number(bucket)];
    requireThat(age>=uint(band.lower_inclusive)&&(band.upper_inclusive===null||age<=uint(band.upper_inclusive)),'Item assigned to wrong age band.');
    const open=positive(item.open,unit),remaining=subtract(subtract(positive(item.original,unit),positive(item.applied,unit)),positive(item.applied_out,unit));
    requireThat(open.n>0n&&eq(open,remaining),'Native open amount disagrees with its applications.');
    const counter=counted[Number(bucket)],side=item.side==='Debit'?'debits':'credits';
    counter[side]=add(counter[side],open);counter.count++;
  }
  for(let i=0;i<bands.length;i++)requireThat(eq(bands[i].debits,counted[i].debits)&&eq(bands[i].credits,counted[i].credits)&&bands[i].count===counted[i].count,'Native age bands disagree with the item list.');
  const debits=bands.reduce((a,b)=>add(a,b.debits),zero(unit,scale)),credits=bands.reduce((a,b)=>add(a,b.credits),zero(unit,scale));
  if(items.length||totals.length){requireThat(totals.length===1,'Missing native aging total.');requireThat(eq(debits,money(totals[0].debits,unit))&&eq(credits,money(totals[0].credits,unit))&&uint(totals[0].item_count)===BigInt(items.length),'Native aging total mismatch.');}
  const check=checks[0]||null;
  if(check){
    requireThat(eq(debits,money(check.open_debits,unit))&&eq(credits,money(check.open_credits,unit)),'Reconciled open amounts differ from aging.');
    requireThat(eq(subtract(money(check.posted_net,unit),money(check.open_net,unit)),money(check.difference,unit)),'Invalid reconciliation difference.');
  }
  if(r.reconciled)for(const row of r.rows)requireThat(parseAmount(row.difference).n===0n,'Green reconciliation has a nonzero difference.');
  return {items,bands,debits,credits,check,reconciled:r.reconciled};
}
export function reportCsv(mode,book,kind,body,unit,rows) {
  const fields=kind==='ledger'?['effective_date','recorded_at','entry_digest','leg_index','class','reason_code','debits','credits','running_balance']:
    ['effective_date','recorded_at','entry','ordinal','side','age_days','bucket','original','applied','applied_out','open'];
  const headers=['mode','book','report','known_at','effective_from','effective_through','account','unit',...fields];
  const lines=[headers,...rows.map(row=>[mode,book,kind,body.known_at,body.effective_from||'',body.effective_through,row.account,unit,...fields.map(f=>row[f])])];
  return '\ufeff'+lines.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';
}
// Invalidating a report also disables its export. A late completion cannot
// repopulate results under new filters, after navigation, or after a failed read.
export function requestGate() { let version=0;return {invalidate:()=>++version,ticket:()=>{const n=++version;return ()=>n===version;}}; }
