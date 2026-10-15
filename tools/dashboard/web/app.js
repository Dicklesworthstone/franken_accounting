import {parseAmount, zero, add, negate, subtract, compare, sum, format, ratio, csvCell, nativeRows, categoryNet} from './amounts.mjs';

const $ = selector => document.querySelector(selector);
const state = {view:'overview', meta:null, overview:null, period:'', unit:'', query:'', type:'all', page:0,
  sort:'code', direction:1, revision:0, detailRevision:0, accountDetail:null, health:null};
const views = {overview:['Overview','Your books, in focus.','Exact balances. Connected evidence. One local workspace.'],
  accounts:['Accounts','A place for every number.','Search your balances, then drill into the entries behind them.'],
  periods:['Fiscal periods','History, without the guesswork.','Calendar boundaries and current period states, exactly as the book reports them.'],
  evidence:['Evidence explorer','Follow the why.','Trace an entry to its resolved legs, source documents, and subsequent lineage.'],
  health:['Integrity checks','Trust, with a defined scope.','Native diagnostics, their exact observations, and no broader promises.']};
const h = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [key,value] of Object.entries(attrs)) {
    if (key.startsWith('on')) node.addEventListener(key.slice(2),value);
    else if (value !== null && value !== undefined && value !== false) node.setAttribute(key,value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
};
const s = (tag, attrs = {}, ...children) => {
  const node = document.createElementNS('http://www.w3.org/2000/svg',tag);
  for (const [key,value] of Object.entries(attrs)) node.setAttribute(key,value);
  for (const child of children.flat(Infinity)) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
};
const badge = (value, kind='neutral') => h('span',{class:`pill ${kind}`},value);
const button = (label, action, cls='button') => h('button',{class:cls,onclick:action,type:'button'},label);
const set = (selector,...nodes) => $(selector).replaceChildren(...nodes.filter(node => node !== null && node !== undefined));
const data = event => event.data;
const at = event => event.coordinate?.known_at ?? 'unknown';
const short = (value,n=12) => String(value).length > n ? String(value).slice(0,n)+'…' : String(value);
const amountNode = value => h('span',{class:'amount',title:value},format(parseAmount(value)));
let queue = Promise.resolve();
let token = new URLSearchParams(location.hash.slice(1)).get('token');
try {
  if (token) { sessionStorage.setItem('fa-dashboard-token',token); history.replaceState(null,'',location.pathname); }
  else token = sessionStorage.getItem('fa-dashboard-token');
} catch { if (token) history.replaceState(null,'',location.pathname); }

function api(path, current = () => true) {
  const operation = queue.catch(() => {}).then(async () => {
    if (!current()) return null;
    const response = await fetch(path,{headers:{Authorization:`Bearer ${token || ''}`},cache:'no-store',credentials:'omit'});
    const body = await response.json();
    if (!response.ok) {
      const error = new Error(body.error || `Native request failed (${response.status}).`);
      error.detail = body.detail; throw error;
    }
    if (body.schema !== 'fa-dashboard/v1' || body.read_only !== true) throw new Error('Unsupported dashboard transport.');
    return body;
  });
  queue = operation; return operation;
}
function query(path,params) { return `/api/${path}?${new URLSearchParams(params)}`; }
function loading(title='Reading the native journal') {
  return h('div',{class:'loading-card'},h('span',{class:'spinner','aria-hidden':'true'}),h('h2',{},title),h('p',{},'The view will appear only after the native read completes.'));
}
function empty(title,message,action) {
  return h('div',{class:'empty'},h('span',{class:'empty-symbol','aria-hidden':'true'},'◎'),h('h2',{},title),h('p',{},message),action || null);
}
function errorBox(error) {
  return h('div',{class:'error-box',role:'alert'},h('strong',{},error.message),
    error.detail?.message ? h('p',{},error.detail.message) : null,
    error.detail?.fix ? h('p',{},'Native guidance: ',error.detail.fix) : null);
}
function notice(error) { $('#notice').hidden=false; set('#notice',errorBox(error)); }
function clearNotice() { $('#notice').hidden=true; set('#notice'); }
let toastTimer;
function toast(message) { clearTimeout(toastTimer); set('#toast',message); $('#toast').hidden=false; toastTimer=setTimeout(()=>$('#toast').hidden=true,3500); }

async function bootstrap() {
  clearNotice();
  try {
    const value=await api('/api/bootstrap'); state.meta=value;
    $('#book-title').textContent=value.title; $('#book-title').title=value.title;
    $('#book-subtitle').textContent=value.mode==='demo' ? 'Synthetic preview' : 'Local owner session';
    $('#demo-banner').hidden=value.mode!=='demo';
    $('#account-count').textContent=data(value.book).accounts;
    const periods=data(value.periods).periods;
    const preferred=periods.find(p=>p.state.toLowerCase()==='open') || periods.at(-1);
    if (!periods.some(p=>p.code===state.period)) state.period=preferred?.code || '';
    set('#period-select',...periods.map(p=>h('option',{value:p.code},p.code)));
    $('#period-select').value=state.period;
    $('#period-select').disabled=!periods.length;
    if (state.period) await loadOverview();
    else { state.overview=null; $('#snapshot-label').textContent=`Book observed at #${at(value.book)}`; render(); }
  } catch(error) { set('#content',errorBox(error),empty('No book data was substituted.','Check the native error and your launch URL. Demo mode is never used as a fallback.')); }
}
async function loadOverview() {
  const revision=++state.revision; state.detailRevision++; $('#drawer').close(); clearNotice();
  const requested=$('#known-at').value.trim();
  if (requested!=='HEAD' && !/^(0|[1-9][0-9]{0,19})$/.test(requested)) {notice(new Error('Enter HEAD or an exact unsigned commit sequence.'));return;}
  state.overview=null;
  set('#content',loading('Reading stock and period activity'));
  $('#snapshot-label').textContent='Reading selected snapshot…';
  try {
    const result=await api(query('overview',{period:state.period,known_at:requested}),()=>revision===state.revision);
    if (!result || revision!==state.revision) return;
    state.overview=result; state.page=0;
    const units=[...new Set(data(result.stock).rows.map(r=>parseAmount(r.debits).unit).concat(data(result.stock).unit_totals.map(r=>r.unit)))].sort();
    if (!units.includes(state.unit)) state.unit=units.includes(data(state.meta.book).base_unit)?data(state.meta.book).base_unit:units[0] || data(state.meta.book).base_unit;
    set('#unit-select',...([...units].length?units:[state.unit]).map(u=>h('option',{value:u},u)));
    $('#unit-select').value=state.unit;
    $('#snapshot-label').textContent=`Pinned to commit #${result.known_at}`;
    render();
  } catch(error) {
    if(revision!==state.revision)return;
    $('#snapshot-label').textContent='Snapshot not loaded'; set('#content',errorBox(error));
  }
}
function navigate(view) {
  if(!views[view])return;
  state.view=view; state.query=''; state.type='all'; state.page=0;
  document.querySelectorAll('[data-view]').forEach(n=>{n.classList.toggle('active',n.dataset.view===view);n.setAttribute('aria-current',n.dataset.view===view?'page':'false');});
  $('#view-name').textContent=views[view][0];$('#page-title').textContent=views[view][1];$('#page-subtitle').textContent=views[view][2];
  render();
}
function panel(title, subtitle, body, action) {
  return h('section',{class:'panel'},h('div',{class:'panel-header'},h('div',{},h('h2',{},title),h('p',{},subtitle)),action || null),body);
}
function render() {
  if(!state.meta)return;
  if(state.view==='periods'){renderPeriods();return;}
  if(state.view==='evidence'){renderEvidenceLanding();return;}
  if(state.view==='health'){renderHealth();return;}
  if(!state.overview){set('#content',empty('Start with a fiscal period.','This book has no selected report yet. Create or open periods with the native CLI, then refresh.'));return;}
  if(state.view==='accounts'){renderAccounts();return;}
  const stock=nativeRows(data(state.overview.stock),state.unit);
  const activity=nativeRows(data(state.overview.activity),state.unit);
  const metrics=[['Asset accounts',categoryNet(stock,'Asset',state.unit),'STOCK','Debit minus credit','↗'],
    ['Liability accounts',categoryNet(stock,'Liability',state.unit,true),'STOCK','Credit minus debit','◫'],
    ['Revenue accounts',categoryNet(activity,'Revenue',state.unit,true),'THIS PERIOD','Credit minus debit','↗'],
    ['Expense accounts',categoryNet(activity,'Expense',state.unit),'THIS PERIOD','Debit minus credit','↘']];
  const cards=h('section',{class:'metrics','aria-label':'Exact native-unit account groups'},...metrics.map(([label,value,tag,formula,icon])=>
    h('article',{class:'metric'},h('div',{class:'metric-label'},label,h('span',{class:'metric-icon','aria-hidden':'true'},icon)),
      h('div',{class:'metric-value',title:format(value,true)},format(value)),
      h('div',{class:'metric-foot'},h('span',{},formula),h('span',{class:'metric-tag'},tag+' · '+state.unit)))));
  const chart=panel('Account landscape','Stock net by account · debit minus credit',h('div',{class:'panel-body'},landscape(stock),
    h('div',{class:'chart-note'},'Select a bar to follow its entries.',h('span',{},'Normalized geometry · exact value labels'))),
    h('div',{class:'legend'},h('span',{},h('i',{class:'swatch'}),'Debit net'),h('span',{},h('i',{class:'swatch credit'}),'Credit net')));
  const mix=panel('The shape of your book','Absolute stock net · grouped by account type',h('div',{class:'panel-body'},composition(stock)));
  const balanced=data(state.overview.stock).balanced===true;
  const table=panel('Accounts at a glance',`Stock through ${data(state.overview.stock).effective_through || state.period} · ${state.unit}`,
    h('div',{},tableNode(stock.slice(0,6)),h('div',{class:'table-footer'},badge(balanced?'Debits equal credits':'Native balance check is red',balanced?'good':'bad'),
      button('View all accounts →',()=>navigate('accounts'),'text-button'))));
  set('#content',cards,h('div',{class:'dashboard-grid'},chart,mix),table,
    h('p',{class:'scope-note'},'Cards summarize the named account types only; they are not classified financial statements. Units are never combined. Stock includes opening history; period activity does not.'));
}
function landscape(rows) {
  const ranked=rows.map(r=>({...r,value:subtract(parseAmount(r.debits),parseAmount(r.credits))})).filter(r=>r.value.n!==0n)
    .sort((a,b)=>compare({...b.value,n:b.value.n<0n?-b.value.n:b.value.n},{...a.value,n:a.value.n<0n?-a.value.n:a.value.n})).slice(0,7);
  if(!ranked.length)return empty('No posted stock in this unit.','Zero is shown as zero, not a sample chart.');
  const maximum=ranked[0].value, height=ranked.length*37+38;
  const plot=s('svg',{viewBox:`0 0 710 ${height}`,class:'landscape',role:'group','aria-label':'Largest absolute account net balances. Select an account for its period contributions.'});
  for(const x of [295,380,465,550])plot.append(s('line',{x1:x,x2:x,y1:9,y2:height-19,class:'grid-line'}));
  ranked.forEach((row,i)=>{
    const y=28+i*37,w=Math.max(row.value.n===0n?0:1,ratio(row.value,maximum,162)),negative=row.value.n<0n;
    const group=s('g',{tabindex:'0',role:'button','aria-label':`${row.code}, ${row.name}, ${format(row.value,true)}. Open account.`},
      s('title',{},`${row.code} · ${row.name}\n${format(row.value,true)}\nDebit minus credit; stock at #${state.overview.known_at}`),
      s('text',{x:0,y,class:'chart-name'},short(row.name,27)),
      s('text',{x:0,y:y+13,class:'chart-value'},row.code),
      s('rect',{x:negative?465-w:465,y:y-10,width:w,height:13,rx:3,class:negative?'bar-credit':'bar-debit'}),
      s('text',{x:708,y,'text-anchor':'end',class:'chart-value'},format(row.value)));
    group.addEventListener('click',()=>showAccount(row.code));
    group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();showAccount(row.code);}});
    plot.append(group);
  });
  plot.append(s('text',{x:465,y:height-1,'text-anchor':'middle'},'0'));
  return plot;
}
function composition(rows) {
  const groups=new Map();
  for(const row of rows){const value=subtract(parseAmount(row.debits),parseAmount(row.credits));groups.set(row.type,add(groups.get(row.type)||zero(state.unit,value.scale),{...value,n:value.n<0n?-value.n:value.n}));}
  const total=[...groups.values()].reduce(add,zero(state.unit));
  const ring=s('svg',{viewBox:'0 0 160 160','aria-hidden':'true'},s('circle',{cx:80,cy:80,r:62,fill:'none','stroke-width':14,class:'donut-track'}));
  let offset=0;const circumference=2*Math.PI*62;
  const list=h('ul',{class:'type-list'});
  for(const [type,value] of groups){const width=ratio(value,total,circumference),cls=typeClass(type);
    ring.append(s('circle',{cx:80,cy:80,r:62,fill:'none','stroke-width':14,'stroke-dasharray':`${width} ${circumference-width}`,
      'stroke-dashoffset':-offset,class:cls},s('title',{},`${type}: ${format(value,true)} absolute net`)));offset+=width;
    list.append(h('li',{class:'type-row'},h('i',{class:`type-dot ${cls}`}),type,h('span',{class:'amount',title:format(value,true)},format(value))));
  }
  return h('div',{},h('div',{class:'composition'},ring,h('div',{class:'donut-center'},h('strong',{},String(rows.length)),h('span',{},'ACCOUNT / UNIT ROWS'))),list,
    h('p',{class:'scope-note'},'Absolute debit-minus-credit balances, not asset allocation or cash flow.'));
}
function typeClass(value){return ['asset','liability','equity','revenue','expense'].includes(value.toLowerCase())?'type-'+value.toLowerCase():'type-other';}
function tableNode(rows,sortable=false){
  const table=h('table'); const headings=[['Account','code'],['Type','type'],['Debits','debits'],['Credits','credits'],['Native net','net']];
  table.append(h('thead',{},h('tr',{},...headings.map(([label,key])=>h('th',{scope:'col',class:['debits','credits','net'].includes(key)?'amount':''},sortable?
    button(label+(state.sort===key?(state.direction===1?' ↑':' ↓'):''),()=>{state.direction=state.sort===key?-state.direction:1;state.sort=key;renderAccountTable();},'sort-button'):label)))));
  table.append(h('tbody',{},...rows.map(row=>h('tr',{},h('td',{},h('button',{class:'account-link',onclick:()=>showAccount(row.code)},h('span',{class:'account-code'},row.code),h('strong',{},row.name),h('span',{class:'arrow','aria-hidden':'true'},'↗'))),
    h('td',{},badge(row.type)),...['debits','credits','net'].map(key=>h('td',{class:'amount'},amountNode(row[key])))))));
  return h('div',{class:'table-wrap'},table);
}
function renderAccounts(){
  const types=[...new Set(data(state.overview.stock).rows.map(r=>r.type))].sort();
  const input=h('input',{type:'search',placeholder:'Search by account name or code…','aria-label':'Filter accounts',value:state.query,oninput:event=>{state.query=event.target.value;state.page=0;renderAccountTable();}});
  const type=h('select',{'aria-label':'Filter account type',onchange:event=>{state.type=event.target.value;state.page=0;renderAccountTable();}},h('option',{value:'all'},'All account types'),...types.map(t=>h('option',{value:t},t)));type.value=state.type;
  set('#content',panel('Chart & balances',`Stock through ${data(state.overview.stock).effective_through || state.period} · one native unit · commit #${state.overview.known_at}`,
    h('div',{},h('div',{class:'filters'},input,type,button('↓ Export CSV',exportAccounts)),h('div',{id:'account-table'}))),
    h('p',{class:'scope-note'},'Drilldowns show the selected period’s contributing legs, which are not the same as the cumulative stock balance above. The net column preserves the native report’s sign convention; a negative value does not itself indicate a problem.'));
  renderAccountTable();
}
function filteredRows(){
  if(!state.overview)return [];
  return nativeRows(data(state.overview.stock),state.unit).filter(r=>(state.type==='all'||r.type===state.type)&&`${r.code} ${r.name}`.toLowerCase().includes(state.query.toLowerCase()))
    .sort((a,b)=>state.direction*(['debits','credits','net'].includes(state.sort)?compare(parseAmount(a[state.sort]),parseAmount(b[state.sort])):String(a[state.sort]).localeCompare(String(b[state.sort]),undefined,{numeric:true})));
}
function renderAccountTable(){
  if(!$('#account-table'))return;
  const rows=filteredRows(),pages=Math.max(1,Math.ceil(rows.length/25));state.page=Math.min(state.page,pages-1);
  const controls=h('div',{},button('←',()=>{state.page=Math.max(0,state.page-1);renderAccountTable();},'small-button'),h('span',{},`  ${state.page+1} / ${pages}  `),button('→',()=>{state.page=Math.min(pages-1,state.page+1);renderAccountTable();},'small-button'));
  set('#account-table',rows.length?tableNode(rows.slice(state.page*25,state.page*25+25),true):empty('No matching accounts.','Try another code, name, unit, or account type.'),
    h('div',{class:'table-footer'},h('span',{},`${rows.length} matching account / unit rows`),controls));
}
function exportAccounts(){
  const rows=filteredRows();const fields=['code','name','type','debits','credits','net','debits_pending','credits_pending'];
  const lines=[['Mode','Book ID','Display name','Period','Known at','Unit',...fields],...rows.map(r=>[state.meta.mode,data(state.meta.book).book_id,state.meta.title,state.period,state.overview.known_at,state.unit,...fields.map(f=>r[f])])];
  const blob=new Blob(['\ufeff'+lines.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n'],{type:'text/csv;charset=utf-8'});
  const url=URL.createObjectURL(blob),link=h('a',{href:url,download:`franken-accounting-${state.meta.mode}-${state.period.replace(/[^a-zA-Z0-9_-]/g,'_')}.csv`});
  document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Exported the filtered view with exact amount strings.');
}
function renderPeriods(){
  const periods=data(state.meta.periods).periods;
  const grid=h('div',{class:'period-grid'},...periods.map(p=>h('article',{class:'panel period-card'},
    h('div',{class:'period-top'},h('h2',{},p.code),badge(p.state,periodStyle(p.state))),
    h('div',{class:'period-dates'},h('div',{},'Start ',h('strong',{},p.start)),h('div',{},'End boundary ',h('strong',{},p.end))),
    h('div',{class:'detail-meta'},badge(p.kind),badge(`FY ${p.fiscal_year}`)),button('Explore period →',()=>{state.period=p.code;$('#period-select').value=p.code;navigate('overview');loadOverview();}))));
  set('#content',periods.length?grid:empty('No fiscal periods yet.','Create periods using the native CLI. The dashboard cannot change period state.'),
    h('p',{class:'scope-note'},`Period metadata is current at commit #${at(state.meta.periods)} and is separate from the report’s historical selector. End boundary is shown as supplied by the native calendar. No closing, reopening, or redating controls are exposed here.`));
}
function periodStyle(value){const v=value.toLowerCase();return v==='open'?'good':v.includes('soft')?'warn':'neutral';}
async function showAccount(account){
  if(!state.overview){toast('Load a period snapshot first.');return;}
  const revision=++state.detailRevision;state.accountDetail=null;set('#drawer-content',h('h2',{id:'drawer-title'},`Account ${account}`),loading('Following this account’s period entries'));
  if(!$('#drawer').open)$('#drawer').showModal();
  try{const result=await api(query('account',{account,period:state.period,known_at:state.overview.known_at}),()=>revision===state.detailRevision);
    if(!result||revision!==state.detailRevision)return;state.accountDetail=result;renderAccountDetail(result);
  }catch(error){if(revision===state.detailRevision)set('#drawer-content',h('h2',{id:'drawer-title'},'Account read failed'),errorBox(error));}
}
function renderAccountDetail(result){
  const report=data(result.report),cells=report.cells.filter(c=>c.unit===state.unit),contributions=report.contributions.filter(c=>parseAmount(c.amount).unit===state.unit);
  const totals=h('div',{class:'detail-stats'},...cells.flatMap(c=>[['Period debits',c.debits],['Period credits',c.credits]].map(([name,value])=>h('div',{class:'detail-stat'},h('span',{},name+' · '+state.unit),h('strong',{},format(parseAmount(value)))))));
  const table=h('table',{},h('thead',{},h('tr',{},...['Entry / effective date','Side','Column','Amount'].map(t=>h('th',{scope:'col'},t)))),
    h('tbody',{},...contributions.map(c=>h('tr',{},h('td',{},h('button',{class:'contribution-link',onclick:()=>showEntry(c.entry)},`${c.class} · ${c.effective_date}`,h('span',{},`#${c.recorded_at} · ${short(c.entry)} · leg ${c.ordinal}`))),
      h('td',{},c.side),h('td',{},badge(c.column,c.column==='pending'?'warn':'neutral')),h('td',{class:'amount'},amountNode(c.amount))))));
  set('#drawer-content',h('div',{class:'eyebrow'},report.account+' / '+report.type),h('h2',{id:'drawer-title'},report.name),
    h('p',{},'Selected-period contributions, directly from the native explanation.'),h('div',{class:'detail-meta'},badge(report.period),badge(`As known at #${report.known_at}`),badge(state.unit)),totals,
    contributions.length?panel('From balance to entry',`${contributions.length} contributing legs · includes posted, pending, and released columns`,h('div',{class:'table-wrap'},table)):
    empty('No contributions in this selection.','This account may still carry opening stock from earlier periods.'),
    h('p',{class:'scope-note'},'These cells describe period movement, not the stock balance. Released reservations are not posted or pending amounts. Select an entry to inspect its current evidence and lineage.'),
    h('div',{class:'hash'},'Native fold digest: '+report.fold_digest));
}
function renderEvidenceLanding(){
  const input=h('input',{placeholder:'32-hex entry handle, or E:…','aria-label':'Entry handle',spellcheck:'false'});
  const open=()=>{const vid=input.value.trim().replace(/^E:/,'');if(!/^[a-fA-F0-9]{32}$/.test(vid)){toast('Enter a complete 32-hex entry handle.');input.focus();return;}state.accountDetail=null;showEntry(vid);};
  input.addEventListener('keydown',e=>{if(e.key==='Enter')open();});
  set('#content',h('div',{class:'empty'},h('span',{class:'empty-symbol','aria-hidden':'true'},'⤳'),h('h2',{},'A number is only the beginning.'),
    h('p',{},'Start from an account’s contributing entries, or paste a known entry handle. Explore its legs, cited documents, review metadata, and supersession links.'),
    h('div',{class:'entry-search'},input,button('Explore entry ↗',open,'button primary')),button('Browse accounts instead →',()=>navigate('accounts'),'text-button')),
    h('p',{class:'scope-note'},'Evidence and lineage reads use their current native coordinates, not the historical report selector. The graph is a relationship view, not a reconstruction of funds flow. Document content is not downloaded.'));
}
async function showEntry(vid){
  const revision=++state.detailRevision;set('#drawer-content',h('h2',{id:'drawer-title'},'Entry & provenance'),loading('Resolving entry and evidence'));
  if(!$('#drawer').open)$('#drawer').showModal();
  try{const result=await api(query('entry',{vid}),()=>revision===state.detailRevision);if(!result||revision!==state.detailRevision)return;renderEntry(result);}
  catch(error){if(revision===state.detailRevision)set('#drawer-content',h('h2',{id:'drawer-title'},'Entry read failed'),errorBox(error));}
}
function evidenceGraph(entry,evidence){
  const legs=entry.legs.slice(0,6),docs=evidence.documents.slice(0,4),height=Math.max(260,Math.max(legs.length,docs.length)*76+20),center=height/2;
  const graph=s('svg',{viewBox:`0 0 650 ${height}`,class:'evidence-graph',role:'group','aria-label':`Entry linked to ${entry.legs.length} resolved legs and ${evidence.documents.length} cited documents. Select a node for its full details.`});
  const node=(label,target,...children)=>{
    const group=s('g',{tabindex:'0',role:'button','aria-label':label},s('title',{},label),...children);
    const reveal=()=>{const detail=document.getElementById(target);if(detail){detail.scrollIntoView({block:'center'});detail.focus({preventScroll:true});}};
    group.addEventListener('click',reveal);
    group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();reveal();}});
    return group;
  };
  legs.forEach((leg,i)=>{const y=12+i*76;graph.append(s('path',{d:`M 205 ${y+30} C 235 ${y+30},225 ${center},255 ${center}`,class:'graph-edge'}),
    node(`Leg ${leg.ordinal}, ${leg.account_name}, ${format(parseAmount(leg.amount),true)}. Show exact details.`,`entry-leg-${i}`,
    s('rect',{x:0,y,width:205,height:61,rx:8,class:'graph-box'}),s('text',{x:12,y:y+17,class:'graph-sub'},`LEG ${leg.ordinal} · ${leg.side.toUpperCase()}`),
    s('text',{x:12,y:y+34,class:'graph-main'},short(leg.account+' · '+leg.account_name,26)),s('text',{x:12,y:y+49,class:'graph-sub'},format(parseAmount(leg.amount),true))));});
  docs.forEach((doc,i)=>{const y=12+i*76;graph.append(s('path',{d:`M 400 ${center} C 430 ${center},422 ${y+30},445 ${y+30}`,class:'graph-edge'}),
    node(`${doc.kind}, ${doc.grade}. Show full document commitment and review metadata.`,`entry-document-${i}`,
    s('rect',{x:445,y,width:205,height:61,rx:8,class:'graph-box'}),s('text',{x:457,y:y+17,class:'graph-sub'},'CITED DOCUMENT'),
    s('text',{x:457,y:y+34,class:'graph-main'},short(doc.kind+' · '+doc.grade,26)),s('text',{x:457,y:y+49,class:'graph-sub'},short(doc.document_oid,24))));});
  graph.append(s('rect',{x:255,y:center-45,width:145,height:90,rx:10,class:'graph-core'}),s('text',{x:327,y:center-16,'text-anchor':'middle',class:'graph-core-text'},entry.class),
    s('text',{x:327,y:center+6,'text-anchor':'middle',class:'graph-core-text'},entry.effective_date),s('text',{x:327,y:center+26,'text-anchor':'middle',class:'graph-core-text'},`Commit #${entry.recorded_at}`));
  return graph;
}
function renderEntry(result){
  const entry=data(result.entry),evidence=data(result.evidence);
  const desc=entry.description?.untrusted_content;
  const legs=h('table',{},h('thead',{},h('tr',{},...['Leg / account','Side','Amount'].map(t=>h('th',{scope:'col'},t)))),h('tbody',{},...entry.legs.map((leg,index)=>h('tr',{id:`entry-leg-${index}`,tabindex:'-1'},h('td',{},`${leg.ordinal} · ${leg.account} · ${leg.account_name}`),h('td',{},leg.side),h('td',{class:'amount'},format(parseAmount(leg.amount),true))))));
  const documents=evidence.documents.map((doc,index)=>h('article',{class:'document-card',id:`entry-document-${index}`,tabindex:'-1'},h('h3',{},doc.kind,badge(doc.counts_toward_minimum?'Counts toward minimum':'Does not count',doc.counts_toward_minimum?'good':'warn')),
    h('div',{class:'detail-meta'},badge(doc.role_name || `Role ${doc.role}`),badge(doc.grade),badge(doc.self_sourced?'Self-sourced':'Not self-sourced',doc.self_sourced?'warn':'neutral')),
    h('div',{class:'hash'},'Document '+doc.document_oid),h('div',{class:'hash'},'Commitment '+doc.doc_commit),h('p',{},`Recorded #${doc.recorded_at} · ${doc.size} bytes · ${doc.reviews.length} review(s) · ${doc.supplements.length} supplement(s)`),
    ...doc.reviews.map(review=>h('p',{class:'hash'},`Reviewed at #${review.recorded_at} by ${review.reviewer} · ${review.attestation_vid}`))));
  const lineage=[...entry.supersedes.map(x=>({...x,direction:'Supersedes'})),...entry.superseded_by.map(x=>({...x,direction:'Superseded by'}))];
  set('#drawer-content',state.accountDetail?button('← Back to account',()=>renderAccountDetail(state.accountDetail),'text-button'):null,
    h('h2',{id:'drawer-title'},'Entry & provenance'),h('div',{class:'hash'},entry.vid),
    h('div',{class:'detail-meta'},badge(entry.class),badge(entry.period || 'Book scope'),badge(`Recorded #${entry.recorded_at}`)),
    h('p',{class:'scope-note'},`Current lineage observed at #${at(result.entry)}; evidence observed at #${at(result.evidence)}. These reads are not pinned to the earlier report snapshot.`),
    desc!==undefined?h('div',{class:'description'},h('small',{},'ENTRY-AUTHORED TEXT · '+entry.description.source),desc):null,
    evidenceGraph(entry,evidence),h('p',{class:'scope-note'},`Showing ${Math.min(6,entry.legs.length)} of ${entry.legs.length} legs and ${Math.min(4,evidence.documents.length)} of ${evidence.documents.length} documents above. Select a node for full details below. Relationships, not cash-flow attribution.`),
    panel('Resolved legs','Exact native amounts · no currency conversion',h('div',{class:'table-wrap'},legs)),
    panel('Evidence closure',`Native minimum: ${evidence.min_documents} document(s) · ${entry.approvals} approval(s)`,
      h('div',{class:'panel-body'},badge(evidence.satisfied?'Native evidence minimum satisfied':'Native evidence minimum not satisfied',evidence.satisfied?'good':'bad'),...documents,
        ...evidence.manual_assertions.map(a=>h('p',{class:'scope-note'},`Manual assertion ${a.attestation_vid} · #${a.recorded_at} · ${a.reason || a.reason_code}`)),
        h('p',{class:'scope-note'},'Meeting the class minimum does not establish authenticity, economic truth, or a signed proof. The dashboard does not retrieve document contents.'))),
    lineage.length?panel('Supersession lineage','Later records do not erase the original.',h('div',{class:'panel-body'},...lineage.map(link=>h('p',{},`${link.direction} · ${link.kind} · ${link.reason || link.reason_code} `,button(short(link.entry),()=>showEntry(link.entry),'text-button'))))):null,
    h('p',{class:'hash'},'Entry digest: '+entry.entry_digest));
}
async function renderHealth(){
  set('#content',loading('Running native triage'));
  const view=state.view;
  try{const result=await api('/api/health',()=>state.view===view);if(!result||state.view!==view)return;
    const report=data(result.report);
    const cards=h('div',{class:'health-grid'},...[['Native triage',report.health],['Daemon',report.daemon],['Due / blocked reversals',`${report.due_reversals} / ${report.blocked_reversals}`]].map(([label,value])=>h('article',{class:'panel health-metric'},h('span',{},label),h('strong',{},value))));
    const checks=report.derived.map(check=>h('article',{class:'check-card'},h('h3',{},check.name,badge(check.status,check.status==='ok'?'good':check.status==='fail'?'bad':'warn')),h('p',{},check.detail),check.fix?h('code',{},check.fix):null));
    const projection=h('div',{id:'projection-result'},h('p',{class:'scope-note'},'Checks have a cost. Run the projection check explicitly; it is never polled in the background.'));
    set('#content',cards,panel('Derived-state observations',`Current native triage at #${at(result.report)}`,h('div',{},...checks)),
      h('div',{class:'detail-actions'},button('Run leg projection check',runProjection,'button primary')),projection,
      h('p',{class:'scope-note'},'Triage and leg projection checks do not certify source immutability, evidence truth, completeness of offline proofs, or accounting judgment. No automatic repair is available.'));
  }catch(error){if(state.view===view)set('#content',errorBox(error));}
}
async function runProjection(){
  set('#projection-result',loading('Checking native leg projections'));
  try{const result=await api('/api/projections',()=>state.view==='health');if(!result||!$('#projection-result'))return;
    const report=result.report,body=report.data,failed=report.failed || (body?.drift?.length??0)>0;
    set('#projection-result',panel(failed?'Projection drift or verification failure':'Leg projections agree with payloads',`Current check at #${body?.known_at ?? at(report)} · leg mirrors and topology only`,
      h('div',{class:'panel-body'},badge(state.meta.mode==='demo'?'Synthetic result — no native verifier ran':failed?'Native red result':'Native projection check passed',failed?'bad':state.meta.mode==='demo'?'warn':'good'),
        body?h('p',{class:'scope-note'},`${body.entries_checked} entries · ${body.legs_checked} legs · ${body.edges_checked} expected edges`):null,
        ...(body?.drift || []).map(d=>h('p',{},d)),report.error?h('pre',{class:'native-json'},JSON.stringify(report.error,null,2)):null)));
  }catch(error){if($('#projection-result'))set('#projection-result',errorBox(error));}
}
function openPalette(){set('#palette-input','');$('#palette-input').value='';renderPalette('');$('#palette').showModal();$('#palette-input').focus();}
function renderPalette(term){
  const options=Object.entries(views).map(([key,[name]])=>({title:name,kind:'View',run:()=>navigate(key)}));
  const seen=new Set();for(const row of state.overview?data(state.overview.stock).rows:[]){if(seen.has(row.code))continue;seen.add(row.code);options.push({title:`${row.code} · ${row.name}`,kind:'Account',run:()=>showAccount(row.code)});}
  const matches=options.filter(o=>o.title.toLowerCase().includes(term.toLowerCase())).slice(0,12);
  set('#palette-results',...matches.map(o=>button([o.title,h('span',{},o.kind)],()=>{$('#palette').close();o.run();},'palette-option')));
  if(!matches.length)set('#palette-results',h('p',{class:'scope-note'},'No matching view or account.'));
}
function theme(value){document.documentElement.dataset.theme=value;$('#theme-button').setAttribute('aria-label',`Switch to ${value==='dark'?'light':'dark'} theme`);try{localStorage.setItem('fa-dashboard-theme',value);}catch{}}
$('#theme-button').addEventListener('click',()=>theme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
try{theme(localStorage.getItem('fa-dashboard-theme') || (matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'));}catch{theme('light');}
document.querySelectorAll('[data-view]').forEach(n=>n.addEventListener('click',()=>navigate(n.dataset.view)));
$('.brand').addEventListener('click',event=>{event.preventDefault();navigate('overview');});
$('#refresh-button').addEventListener('click',()=>{$('#known-at').value='HEAD';bootstrap();});
$('#period-select').addEventListener('change',event=>{state.period=event.target.value;loadOverview();});
$('#unit-select').addEventListener('change',event=>{state.unit=event.target.value;state.page=0;state.detailRevision++;$('#drawer').close();render();});
$('#apply-snapshot').addEventListener('click',()=>{if(state.period)loadOverview();});
$('#known-at').addEventListener('keydown',event=>{if(event.key==='Enter'&&state.period)loadOverview();});
$('#close-drawer').addEventListener('click',()=>$('#drawer').close());
$('#drawer').addEventListener('close',()=>{state.detailRevision++;});
$('#search-button').addEventListener('click',openPalette);$('#close-palette').addEventListener('click',()=>$('#palette').close());
$('#palette-input').addEventListener('input',event=>renderPalette(event.target.value));
$('#palette').addEventListener('keydown',event=>{const options=[...document.querySelectorAll('.palette-option')];if(!options.length)return;const index=options.indexOf(document.activeElement);
  if(event.key==='ArrowDown'){event.preventDefault();options[(index+1)%options.length].focus();}
  if(event.key==='ArrowUp'){event.preventDefault();options[(index-1+options.length)%options.length].focus();}
  if(event.key==='Enter'&&document.activeElement===$('#palette-input')){event.preventDefault();options[0].click();}});
document.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='k'){event.preventDefault();if(!$('#drawer').open&&!$('#palette').open)openPalette();}});
$('#tour-button').addEventListener('click',()=>{const row=state.overview?nativeRows(data(state.overview.stock),state.unit)[0]:null;if(row)showAccount(row.code);else navigate('accounts');});
bootstrap();
