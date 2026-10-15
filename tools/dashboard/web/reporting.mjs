import {parseAmount, format, compare, ratio, zero} from './amounts.mjs';
import {ledgerModel, agingModel, bandLabel, reportCsv, requestGate, requireThat} from './report-model.mjs';

const $=selector=>document.querySelector(selector);
const el=(tag,attrs={},...children)=>{
  const n=document.createElement(tag);
  for(const [key,value] of Object.entries(attrs)){
    if(key.startsWith('on'))n.addEventListener(key.slice(2),value);
    else if(value!==false&&value!==null&&value!==undefined)n.setAttribute(key,value===true?'':value);
  }
  for(const child of children.flat(Infinity))if(child!==null&&child!==undefined)n.append(child instanceof Node?child:document.createTextNode(String(child)));
  return n;
};
const svg=(tag,attrs={},...children)=>{
  const n=document.createElementNS('http://www.w3.org/2000/svg',tag);
  for(const [key,value] of Object.entries(attrs))n.setAttribute(key,value);
  for(const child of children.flat(Infinity))n.append(child instanceof Node?child:document.createTextNode(String(child)));
  return n;
};
const replace=(selector,...nodes)=>$(selector).replaceChildren(...nodes);
const button=(label,action,cls='button')=>el('button',{type:'button',class:cls,onclick:action},label);
const pill=(label,cls='')=>el('span',{class:'pill '+cls},label);
const note=text=>el('p',{class:'scope-note'},text);
const panel=(title,subtitle,body,action)=>el('section',{class:'panel'},el('div',{class:'panel-head'},el('div',{},el('h2',{},title),el('p',{},subtitle)),action||null),body);
const money=value=>el('span',{class:'amount',title:value},format(parseAmount(value)));
const shorten=value=>String(value).slice(0,12)+'…';
const state={view:'ledger',meta:null,loaded:null,ready:false,query:'',side:'all',bucket:'all',day:'',page:0,ageSort:'oldest'};
const gate=requestGate(),detailGate=requestGate();
let queue=Promise.resolve(),toastTimer;
const fragment=new URLSearchParams(location.hash.slice(1));
let token=fragment.get('token');
try{
  if(token){sessionStorage.setItem('fa-dashboard-token',token);history.replaceState(null,'',location.pathname+'#ledger');}
  else token=sessionStorage.getItem('fa-dashboard-token');
}catch{if(token)history.replaceState(null,'',location.pathname+'#ledger');}
function toast(message){clearTimeout(toastTimer);$('#toast').hidden=false;replace('#toast',message);toastTimer=setTimeout(()=>$('#toast').hidden=true,4000);}
function api(path,current=()=>true){
  const task=queue.catch(()=>{}).then(async()=>{
    if(!current())return null;
    const response=await fetch(path,{headers:{Authorization:`Bearer ${token||''}`},credentials:'omit',cache:'no-store'});
    const body=await response.json();
    if(!response.ok){const error=new Error(body.error||`Native read failed (${response.status}).`);error.detail=body.detail;throw error;}
    requireThat(body.schema==='fa-dashboard/v1'&&body.read_only===true,'Unsupported dashboard response.');
    if(state.meta)requireThat(body.mode===state.meta.mode,'Source mode changed; restart the dashboard.');
    return body;
  });
  queue=task;return task;
}
function failure(error){return el('div',{class:'error',role:'alert'},el('strong',{},error.message),
  error.detail?.message?el('p',{},error.detail.message):null,error.detail?.fix?el('p',{},'Native guidance: '+error.detail.fix):null,
  note('No replacement data or automatic repair was used.'));
}
function empty(title,message){return el('div',{class:'empty'},el('h2',{},title),el('p',{},message));}
function loading(){return el('div',{class:'empty'},el('span',{class:'spinner','aria-hidden':'true'}),el('h2',{},'Reading the native report'),el('p',{},'The result will retain its exact selection and recorded snapshot.'));}
function invalidate(){
  gate.invalidate();detailGate.invalidate();state.loaded=null;
  $('#entry-dialog').close();$('#run').disabled=!state.ready;
  $('#selection-state').textContent='Selection changed · run to load a new result';
  replace('#result',empty('Ready for your next question.','Choose explicit dates and a snapshot, then run the report. Previous results are not relabeled under new selections.'));
}
function route(){
  state.view=location.hash==='#aging'?'aging':'ledger';invalidate();
  document.querySelectorAll('[data-report]').forEach(link=>{const active=link.dataset.report===state.view;link.classList.toggle('active',active);link.setAttribute('aria-current',active?'page':'false');});
  const aging=state.view==='aging';
  $('#breadcrumb').textContent=aging?'Open-item aging':'General ledger';
  $('#title').textContent=aging?'See what remains open.':'Every movement, accounted for.';
  $('#subtitle').textContent=aging?'Effective-date age bands, exact open amounts, and native control reconciliation.':'Opening stock, posted movements, and closing stock at one exact snapshot.';
  $('#from-field').hidden=aging;$('#date-from').disabled=aging;$('#date-from').required=!aging;
  $('#buckets-field').hidden=!aging;$('#buckets').disabled=!aging;
  $('#to-label').textContent=aging?'As of, inclusive':'To, inclusive';
  $('#aging-note').textContent=aging?'Age is measured from the effective date, not a contractual due date. Debit and credit open items remain separate.':'All amounts stay in their native unit. No currency conversion. Running balances use debit minus credit.';
  if(state.ready)load();
}
function selection(){
  const known=$('#snapshot').value.trim();
  requireThat(known==='HEAD'||(/^(0|[1-9][0-9]{0,19})$/.test(known)&&BigInt(known)<2n**64n),'Enter HEAD or an exact unsigned 64-bit commit sequence.');
  const base={account:$('#account').value.trim(),known_at:known};
  requireThat(base.account&&!base.account.startsWith('-')&&!base.account.includes(','),'Select one explicit account.');
  const unit=$('#unit').value.trim();requireThat(unit&&!/[,\s]/.test(unit),'Select one native unit code.');
  return state.view==='ledger'?{...base,unit,from:$('#date-from').value,to:$('#date-to').value}:
    {...base,unit,as_of:$('#date-to').value,buckets:$('#buckets').value.replace(/\s/g,'')};
}
async function load(){
  if(!state.ready||!$('#selection').reportValidity())return;
  invalidate();const current=gate.ticket(),kind=state.view;
  let selected;
  try{selected=selection();}catch(error){replace('#result',failure(error));return;}
  $('#run').disabled=true;$('#selection-state').textContent='Reading selected scope…';replace('#result',loading());
  try{
    const params={...selected};if(kind==='aging')delete params.unit;
    const result=await api(`/api/${kind}?${new URLSearchParams(params)}`,current);
    if(!result||!current())return;
    requireThat(result.report.book===state.meta.book.book,'Report belongs to a different book.');
    const model=kind==='ledger'?ledgerModel(result.report,selected):agingModel(result.report,result.reconciliation,selected.unit);
    if(kind==='aging'){
      requireThat(result.report.data.account===selected.account&&result.report.data.effective_through===selected.as_of,'Aging selection mismatch.');
      requireThat(selected.known_at==='HEAD'||result.report.data.known_at===selected.known_at,'Aging snapshot mismatch.');
    }
    state.loaded={kind,selected,result,model};state.query='';state.side='all';state.bucket='all';state.day='';state.page=0;
    $('#snapshot').value=result.report.data.known_at;
    $('#selection-state').textContent=`Pinned to commit #${result.report.data.known_at}`;
    render();
  }catch(error){if(current()){state.loaded=null;$('#selection-state').textContent='Report not loaded';replace('#result',failure(error));}}
  finally{if(current())$('#run').disabled=false;}
}
function metric(label,value,caption){return el('article',{class:'metric'},el('span',{},label),el('strong',{title:value},value),el('small',{},caption));}
function render(){
  const loaded=state.loaded;if(!loaded)return;
  const {kind,selected,result,model}=loaded,b=result.report.data;
  const title=kind==='ledger'?(model?.cell.name||selected.account):result.reconciliation.data.name;
  const exportButton=button('↓ Export visible rows',exportVisible);exportButton.id='export';
  const scope=el('div',{class:'scope-bar'},el('div',{},el('h2',{},selected.account+' · '+title),
    el('small',{},`${kind==='ledger'?b.effective_from+' → ':''}${b.effective_through} · ${selected.unit} · commit #${b.known_at} · ${state.meta.mode==='demo'?'SYNTHETIC DEMO':'native read'}`)),exportButton);
  if(kind==='ledger'&&!model){exportButton.disabled=true;replace('#result',scope,empty('No account/unit cell in this scope.','An absent cell is not presented as a zero balance. Choose a different selection.'));return;}
  let cards,chart,check=null;
  if(kind==='ledger'){
    cards=el('section',{class:'metrics','aria-label':'Native ledger totals'},metric('Opening stock',format(model.opening),'Before selected movements · '+selected.unit),
      metric('Posted debits',format(model.debits),'Selected interval · '+selected.unit),metric('Posted credits',format(model.credits),'Selected interval · '+selected.unit),metric('Closing stock',format(model.closing),'Through inclusive cutoff · '+selected.unit));
    chart=panel('The balance over time','Daily closing balances at the selected recorded snapshot',el('div',{class:'panel-body'},el('div',{class:'plot-scroll'},trend(model)),
      el('div',{class:'chart-range'},el('span',{},'Lowest daily / opening value ',el('strong',{},format(model.min,true))),el('span',{},'Highest daily / opening value ',el('strong',{},format(model.max,true)))),
      el('div',{class:'chart-inspect',id:'chart-inspect'},'Hover or focus a point for its exact value. Select it to filter movements by date.'),
      note(`${model.dayCount} movement days. ${model.sampled?'Chart uses a bounded first/min/max/last envelope of daily closings; all movement rows remain available.':'All daily closing points are shown.'} Intra-day movements remain in the table; this is not a claim about what was known on each recorded day.`)));
  }else{
    const c=model.check;
    cards=el('section',{class:'metrics','aria-label':'Native aging totals'},metric('Debit open items',format(model.debits),'Never netted with credit items · '+selected.unit),
      metric('Credit open items',format(model.credits),'Never treated as receivables · '+selected.unit),metric('Open items',String(model.items.length),'Selected account / native unit'),
      metric('Control difference',c?format(parseAmount(c.difference)):'Not reported',c?'Posted net − open net · '+selected.unit:'No reconciliation row for this unit'));
    const verdict=!model.reconciled?'Native reconciliation reports a difference':c?'Native account reconciliation agrees':'No reconciliation row for this unit';
    check=el('section',{class:'notice '+(!model.reconciled?'bad':state.meta.mode!=='demo'&&c?'good':'')},el('strong',{},state.meta.mode==='demo'?'Synthetic reconciliation example':verdict),
      el('p',{},c?`Posted net ${format(parseAmount(c.posted_net),true)} · open net ${format(parseAmount(c.open_net),true)} · difference ${format(parseAmount(c.difference),true)}.`:'A missing unit row is not a verified zero.'),
      el('p',{},`Aging and reconciliation use the same account, effective cutoff, bucket bounds, and commit #${b.known_at}. The account-wide native verdict is ${model.reconciled?'reconciled':'not reconciled'}, including units not currently displayed. This does not establish evidence truth or overdue status.`));
    chart=panel('Age of the open balance','Civil days since each item’s effective date · choose a band to inspect',el('div',{class:'panel-body'},el('div',{class:'plot-scroll'},ageChart(model)),
      note('Blue shows debit open amounts; green shows credit open amounts. Age is not days past due. Summary cards retain the whole account/unit scope when you filter the table.')),
      el('div',{class:'legend'},el('span',{},el('i',{}),'Debit'),el('span',{},el('i',{class:'credit'}),'Credit')));
  }
  const search=el('input',{type:'search',placeholder:kind==='ledger'?'Filter by date, class or digest…':'Filter by date or entry handle…','aria-label':'Filter report rows',oninput:e=>{state.query=e.target.value;state.page=0;renderTable();}});
  const filters=el('div',{class:'table-controls'},search);
  if(kind==='aging'){
    const side=el('select',{'aria-label':'Open-item side',onchange:e=>{state.side=e.target.value;state.page=0;renderTable();}},...['all','Debit','Credit'].map(value=>el('option',{value},value==='all'?'Both sides':value+' only')));
    const order=el('select',{'aria-label':'Sort open items',onchange:e=>{state.ageSort=e.target.value;state.page=0;renderTable();}},el('option',{value:'oldest'},'Oldest first'),el('option',{value:'largest'},'Largest open first'));
    order.value=state.ageSort;filters.append(side,order);
  }
  filters.append(button('Clear chart filter',()=>{state.bucket='all';state.day='';state.page=0;renderTable();},'quiet'));
  const table=panel(kind==='ledger'?'Posted movements':'Open-item detail',kind==='ledger'?`${model.lines.length} native movement rows · running balances retain the complete scope`:`${model.items.length} open items · inspect each entry’s current evidence`,
    el('div',{},filters,el('div',{id:'report-table'})));
  replace('#result',scope,cards,...(check?[check]:[]),chart,table,note('The charts and export are a presentation of native report data, not signed certificates. No posting, settlement, close or repair is requested.'));
  renderTable();
}
function trend(model){
  const plot=svg('svg',{viewBox:'0 0 1000 260',class:'chart',role:'group','aria-label':'Daily closing balance chart. Exact values available on focus.'});
  for(const y of [25,85,145,205])plot.append(svg('line',{x1:25,x2:975,y1:y,y2:y,class:'grid'}));
  const points=model.points.map(p=>({...p,cx:25+p.x*950,cy:205-p.y*180}));
  const path=points.map((p,i)=>i?`H ${p.cx.toFixed(3)} V ${p.cy.toFixed(3)}`:`M ${p.cx.toFixed(3)} ${p.cy.toFixed(3)}`).join(' ');
  plot.append(svg('path',{d:path,class:'trend'}));
  points.forEach(p=>{
    const label=`${p.date} · ${p.label} · ${format(p.amount,true)}`;
    const dot=svg('circle',{cx:p.cx,cy:p.cy,r:3.5,class:'chart-point',tabindex:'0',role:'button','aria-label':label+'. Filter movements on this date.'},svg('title',{},label));
    const inspect=()=>{const node=$('#chart-inspect');if(node)node.textContent=label;};
    const choose=()=>{inspect();state.day=p.date;state.page=0;renderTable();};
    dot.addEventListener('mouseenter',inspect);dot.addEventListener('focus',inspect);dot.addEventListener('click',choose);
    dot.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choose();}});plot.append(dot);
  });
  plot.append(svg('text',{x:25,y:248},model.points[0].date),svg('text',{x:975,y:248,'text-anchor':'end'},model.points.at(-1).date));
  return plot;
}
function ageChart(model){
  let max=zero(state.loaded.selected.unit);
  for(const band of model.bands)for(const value of [band.debits,band.credits])if(compare(value,max)>0)max=value;
  const plot=svg('svg',{viewBox:`0 0 1000 ${model.bands.length*62+18}`,class:'chart',role:'group','aria-label':'Open amounts by effective-date age band and side. Select a band to filter items.'});
  model.bands.forEach((band,i)=>{
    const y=i*62+15,label=bandLabel(band);
    const group=svg('g',{tabindex:'0',role:'button','aria-label':`${label}. Debit ${format(band.debits,true)}. Credit ${format(band.credits,true)}. Filter open items.`},
      svg('title',{},`${label}: ${band.count} items`),svg('text',{x:0,y:y+17},label),
      svg('line',{x1:150,x2:760,y1:y+40,y2:y+40,class:'grid'}),
      svg('rect',{x:150,y,width:ratio(band.debits,max,600),height:12,rx:3,class:'debit'}),
      svg('rect',{x:150,y:y+20,width:ratio(band.credits,max,600),height:12,rx:3,class:'credit'}),
      svg('text',{x:995,y:y+10,'text-anchor':'end'},'Dr '+format(band.debits)),svg('text',{x:995,y:y+30,'text-anchor':'end'},'Cr '+format(band.credits)));
    const choose=()=>{state.bucket=String(band.index);state.page=0;renderTable();};group.addEventListener('click',choose);
    group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choose();}});plot.append(group);
  });
  return plot;
}
function visibleRows(){
  const loaded=state.loaded;if(!loaded||!loaded.model)return [];
  const q=state.query.toLowerCase();
  if(loaded.kind==='ledger')return loaded.model.lines.filter(row=>(!state.day||row.effective_date===state.day)&&`${row.effective_date} ${row.class} ${row.entry_digest}`.toLowerCase().includes(q));
  return loaded.model.items.filter(row=>(state.bucket==='all'||row.bucket===state.bucket)&&(state.side==='all'||row.side===state.side)&&`${row.effective_date} ${row.entry}`.toLowerCase().includes(q))
    .sort((a,b)=>state.ageSort==='largest'?compare(parseAmount(b.open),parseAmount(a.open)):(BigInt(a.age_days)===BigInt(b.age_days)?0:BigInt(a.age_days)>BigInt(b.age_days)?-1:1));
}
function renderTable(){
  if(!state.loaded||!$('#report-table'))return;
  const kind=state.loaded.kind,rows=visibleRows(),pages=Math.max(1,Math.ceil(rows.length/25));state.page=Math.min(state.page,pages-1);
  const headers=kind==='ledger'?['Effective / recorded','Entry / leg','Class','Debits','Credits','Running balance']:['Effective / age','Entry / leg','Side','Original','Applied in / out','Still open'];
  const table=el('table',{},el('thead',{},el('tr',{},...headers.map((label,i)=>el('th',{scope:'col',class:i>=3?'amount':''},label)))));
  table.append(el('tbody',{},...rows.slice(state.page*25,state.page*25+25).map(row=>kind==='ledger'?
    el('tr',{},el('td',{},row.effective_date,el('span',{class:'subtext'},`Recorded #${row.recorded_at}`)),
      el('td',{},el('details',{},el('summary',{},shorten(row.entry_digest)+` · leg ${row.leg_index}`),el('div',{class:'hash'},row.entry_digest),note('This is a full entry digest, not a 32-hex entry handle.'))),
      el('td',{},row.class,el('span',{class:'subtext'},row.reason_code)),...['debits','credits','running_balance'].map(key=>el('td',{class:'amount'},money(row[key])))):
    el('tr',{},el('td',{},row.effective_date,el('span',{class:'subtext'},`${row.age_days} days old`)),
      el('td',{},el('button',{type:'button',class:'entry-link',onclick:()=>showEntry(row.entry)},shorten(row.entry)+` · leg ${row.ordinal}`,el('span',{class:'subtext'},`Recorded #${row.recorded_at} ↗`))),
      el('td',{},pill(row.side)),el('td',{class:'amount'},money(row.original)),el('td',{class:'amount'},money(row.applied),el('span',{class:'subtext'},'out '+format(parseAmount(row.applied_out)))),el('td',{class:'amount'},money(row.open))))));
  const prev=button('←',()=>{state.page--;renderTable();}),next=button('→',()=>{state.page++;renderTable();});prev.disabled=state.page===0;next.disabled=state.page>=pages-1;
  prev.setAttribute('aria-label','Previous report page');next.setAttribute('aria-label','Next report page');
  const scope=state.day?` · date ${state.day}`:state.bucket!=='all'?` · ${bandLabel(state.loaded.model.bands[Number(state.bucket)])}`:'';
  replace('#report-table',rows.length?el('div',{class:'table-wrap'},table):empty('No matching rows.','Clear the table filters or choose another report selection.'),
    el('div',{class:'table-footer'},el('span',{},`${rows.length} visible rows${scope}`),el('div',{class:'pagination'},prev,`Page ${state.page+1} of ${pages}`,next)));
  $('#export').disabled=!rows.length;
}
function exportVisible(){
  const loaded=state.loaded;if(!loaded)return;
  const csv=reportCsv(state.meta.mode,loaded.result.report.book,loaded.kind,loaded.result.report.data,loaded.selected.unit,visibleRows());
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));
  const link=el('a',{href:url,download:`franken-${state.meta.mode}-${loaded.kind}-${loaded.result.report.data.known_at}.csv`});
  document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Exported the visible rows with their original report scope.');
}
async function showEntry(vid){
  const current=detailGate.ticket();replace('#entry-body',loading());if(!$('#entry-dialog').open)$('#entry-dialog').showModal();
  try{
    const value=await api('/api/entry?'+new URLSearchParams({vid}),current);if(!value||!current())return;
    requireThat(value.entry.book===state.meta.book.book&&value.evidence.book===value.entry.book,'Entry belongs to a different book.');
    const e=value.entry.data,d=value.evidence.data;
    requireThat(e.vid===vid&&d.entry===vid&&d.entry_digest===e.entry_digest,'Entry and evidence identities disagree.');
    const table=el('table',{},el('thead',{},el('tr',{},...['Account','Side','Amount'].map(t=>el('th',{scope:'col'},t)))),el('tbody',{},...e.legs.map(leg=>el('tr',{},el('td',{},`${leg.account} · ${leg.account_name}`),el('td',{},leg.side),el('td',{class:'amount'},format(parseAmount(leg.amount),true))))));
    replace('#entry-body',el('h2',{},e.class+' · '+e.effective_date),el('div',{class:'hash'},vid),
      note(`Recorded #${e.recorded_at}. Current entry/lineage observation #${value.entry.coordinate.known_at}; evidence observation #${value.evidence.coordinate.known_at}. These are not historical aging observations.`),
      e.description?el('div',{class:'untrusted'},el('small',{},'ENTRY-AUTHORED TEXT · '+e.description.source),e.description.untrusted_content):el('div'),
      panel('Resolved legs','Exact native amounts, without conversion',el('div',{class:'table-wrap'},table)),
      pill(state.meta.mode==='demo'?'Synthetic evidence example':d.satisfied?'Native evidence minimum satisfied':'Native evidence minimum not satisfied',state.meta.mode==='demo'?'warn':d.satisfied?'good':'bad'),
      ...d.documents.map(doc=>el('article',{class:'document'},el('h3',{},doc.kind+' · '+doc.grade),el('div',{class:'hash'},'Document '+doc.document_oid),el('div',{class:'hash'},'Commitment '+doc.doc_commit),
        note(`${doc.size} bytes · recorded #${doc.recorded_at} · ${doc.reviews.length} reviews. ${doc.self_sourced?'Self-sourced.':'Not self-sourced.'}`))),
      note('Document content is not downloaded. Evidence minimums and reconciliation do not establish authenticity or economic truth.'),el('div',{class:'hash'},'Entry digest '+e.entry_digest));
  }catch(error){if(current())replace('#entry-body',failure(error));}
}
async function connect(){
  $('#run').disabled=true;
  try{
    const meta=await api('/api/bootstrap');state.meta=meta;
    $('#book-name').textContent=meta.title;$('#book-name').title=meta.title;$('#book-mode').textContent=meta.mode==='demo'?'Synthetic preview':'Local owner session';$('#demo-warning').hidden=meta.mode!=='demo';
    const periods=meta.periods.data.periods,period=periods.find(p=>p.state.toLowerCase()==='open')||periods.at(-1);
    if(period){
      const preview=await api('/api/overview?'+new URLSearchParams({period:period.code,known_at:'HEAD'}));
      const rows=preview.stock.data.rows,codes=new Map(rows.map(row=>[row.code,row.name]));
      replace('#account-options',...[...codes].map(([code,name])=>el('option',{value:code},name)));
      const units=[...new Set(rows.map(row=>parseAmount(row.debits).unit))];
      replace('#unit-options',...units.map(unit=>el('option',{value:unit},unit)));
      $('#account').value=rows[0]?.code||'';$('#unit').value=meta.book.data.base_unit;
      $('#date-from').value=period.start;$('#date-to').value=preview.stock.data.effective_through||'';
      $('#snapshot').value=preview.known_at;
    }else $('#unit').value=meta.book.data.base_unit;
    state.ready=true;$('#run').disabled=false;
    if($('#account').value&&$('#date-to').value)await load();else invalidate();
  }catch(error){$('#connection-error').hidden=false;replace('#connection-error',failure(error));$('#selection-state').textContent='Connection not ready';}
}
function setTheme(value){document.documentElement.dataset.theme=value;$('#theme').setAttribute('aria-label',`Switch to ${value==='dark'?'light':'dark'} theme`);try{localStorage.setItem('fa-dashboard-theme',value);}catch{}}
try{setTheme(localStorage.getItem('fa-dashboard-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'));}catch{setTheme('light');}
$('#theme').addEventListener('click',()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
$('#selection').addEventListener('input',invalidate);
$('#selection').addEventListener('submit',e=>{e.preventDefault();load();});
$('#latest').addEventListener('click',()=>{$('#snapshot').value='HEAD';invalidate();load();});
$('#close-entry').addEventListener('click',()=>$('#entry-dialog').close());
$('#entry-dialog').addEventListener('close',()=>detailGate.invalidate());
window.addEventListener('hashchange',route);
route();connect();
