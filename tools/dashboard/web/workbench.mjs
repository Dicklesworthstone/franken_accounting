import {parseAmount, zero, add, subtract, compare, sum, format, ratio, csvCell, categoryNet} from './amounts.mjs';
import {ledgerModel, agingModel, bandLabel, reportCsv, requestGate, dayNumber} from './report-model.mjs';
import {stockRows, comparisonModel, comparisonCsv, accountGraph, entryGraph, snapshot, sequence} from './workbench-model.mjs';
import {layoutGraph, graphBounds} from './graph-layout.mjs';

const $ = selector => document.querySelector(selector);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (value !== false && value !== null && value !== undefined) node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined && child !== false) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
};
const svg = (tag, attrs = {}, ...children) => {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
};
const paths = {
  overview:'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  ledger:'M5 3h14v18H5zM8 8h8M8 12h8M8 16h5',
  aging:'M12 3a9 9 0 1 0 9 9h-9V3zm4 0v5h5a9 9 0 0 0-5-5z',
  time:'M4 8a9 9 0 1 1-1 7M4 3v5h5M12 7v5l3 2',
  graph:'M8 11l8-5M8 13l8 5M6 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6m13-7a3 3 0 1 0 0 6 3 3 0 0 0 0-6m0 14a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
  calendar:'M4 5h16v16H4zM8 2v6M16 2v6M4 10h16M8 14h2M14 14h2',
  shield:'m12 2 8 3v6c0 5-8 11-8 11S4 16 4 11V5zM8 11l3 3 5-6',
  search:'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14m5 12 6 6',
  arrow:'M5 12h14m-6-6 6 6-6 6', chevron:'m9 5 7 7-7 7',
  diagonal:'M6 18 18 6M6 6h12v12', down:'M12 3v14m-5-5 5 5 5-5M4 19v3h16v-3',
  refresh:'M3 10a9 9 0 0 1 15-6l3 4M21 3v5h-5M21 14a9 9 0 0 1-15 6l-3-4M3 21v-5h5',
  scope:'M4 9V4h5M15 4h5v5M20 15v5h-5M9 20H4v-5M9 9h6v6H9z',
  lock:'M7 10V7a5 5 0 0 1 10 0v3M5 10h14v11H5zM12 14v3',
  branch:'M6 2v14a4 4 0 0 0 4 4h8M6 10h8a4 4 0 0 0 4-4V2',
  book:'M3 4h7l2 2 2-2h7v16h-7l-2 2-2-2H3zM12 6v16',
  help:'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20M9 8a3 3 0 1 1 4 3c-1 .4-1 1-1 2M12 17h.01',
  moon:'M20 15A9 9 0 0 1 9 4a9 9 0 1 0 11 11z',
  sun:'M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10M12 1v2M12 21v2M1 12h2M21 12h2M4 4l2 2M18 18l2 2M20 4l-2 2M6 18l-2 2',
  wallet:'M4 5h15v4M3 8h18v13H3zM16 13h5v4h-5z',
  trend:'m3 17 6-6 4 3 8-10M15 4h6v6',
  layers:'m12 3 10 5-10 5L2 8zM2 12l10 5 10-5M2 16l10 5 10-5',
  check:'m5 12 4 4L20 5', warning:'m12 3 10 18H2zM12 9v5M12 17h.01',
  copy:'M8 8h13v13H8zM16 8V3H3v13h5',
  plus:'M12 5v14M5 12h14', minus:'M5 12h14', fit:'M3 9V3h6M15 3h6v6M21 15v6h-6M9 21H3v-6',
  person:'M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8M4 22v-3a8 8 0 0 1 16 0v3',
  document:'M5 2h9l5 5v15H5zM14 2v6h5M8 12h8M8 16h8',
  list:'M8 5h13M8 12h13M8 19h13M3 5h.1M3 12h.1M3 19h.1',
};
function icon(name) { return svg('svg', {viewBox:'0 0 24 24', class:'icon', 'aria-hidden':'true'}, svg('path', {d:paths[name] || paths.ledger})); }
const button = (label, action, cls='button', symbol) => el('button', {type:'button',class:cls,onclick:action}, symbol?icon(symbol):null,label);
const tag = (text,cls='',symbol) => el('span',{class:'tag '+cls},symbol?icon(symbol):null,text);
const body = event => event.data;
const at = event => event?.coordinate?.known_at || 'unknown';
const short = (value,n=13) => {const text=String(value);return text.length>n?text.slice(0,n-1)+'…':text;};
const exact = value => typeof value==='string'?parseAmount(value):value;
const moneyText = (value,unit=false) => format(exact(value),unit);
const abs = amount => ({...amount,n:amount.n<0n?-amount.n:amount.n});
const amount = value => el('span',{class:'numeric',title:moneyText(value,true)},moneyText(value));
const set = (target,...children) => (typeof target==='string'?$(target):target).replaceChildren(...children.flat().filter(x=>x!==null&&x!==undefined));
const mainGate=requestGate(), detailGate=requestGate(), spotlightGate=requestGate(), bootGate=requestGate();
let graphCleanup=()=>{}, queue=Promise.resolve(), toastTimer, commandOptions=[], commandIndex=0;
let token=new URLSearchParams(location.hash.slice(1)).get('token');
try {if(token){sessionStorage.setItem('fa-dashboard-token',token);history.replaceState(null,'',location.pathname);}else token=sessionStorage.getItem('fa-dashboard-token');}
catch {if(token)history.replaceState(null,'',location.pathname);}
const names={overview:['Overview','See the bigger picture.','Your balances, their history, and the evidence that connects them.'],
  accounts:['Accounts','Every account, in context.','Exact native balances. Select an account to follow the underlying entries.'],
  ledger:['General ledger','Follow the movement.','Opening stock, every posted leg, and closing stock. Nothing quietly netted away.'],
  aging:['Open-item aging','What remains open.','See the remaining amounts, their effective-date ages, and the control reconciliation.'],
  compare:['Time lens','Same period. A new perspective.','Hold effective time still. Compare what the ledger knew at two recorded snapshots.'],
  graph:['Evidence graph','Everything is connected.','Explore the entries and source references behind a number. Not an inferred funds-flow map.'],
  periods:['Fiscal periods','A place in time.','The native calendar and its current period states. Your historical reports stay separate.'],
  health:['Integrity','Trust the scope, not a badge.','Native diagnostics with explicit observations. No automatic repair or implied certification.']};
const initial=location.hash.slice(1);
const S={view:names[initial]?initial:'overview',meta:null,overview:null,period:'',unit:'',known:'HEAD',account:'',from:'',to:'',before:'',buckets:'30,60,90',result:null,entryFocus:null,scope:null};

function announce(message){$('#announcer').textContent=message;}
function toast(message){clearTimeout(toastTimer);set('#toast',message);$('#toast').hidden=false;toastTimer=setTimeout(()=>$('#toast').hidden=true,4000);}
function api(path,params={},current=()=>true){
  const suffix=Object.keys(params).length?'?'+new URLSearchParams(params):'';
  const task=queue.catch(()=>{}).then(async()=>{
    if(!current())return null;
    const response=await fetch('/api/'+path+suffix,{headers:{Authorization:'Bearer '+(token||'')},credentials:'omit',cache:'no-store'});
    const result=await response.json();
    if(!response.ok){const error=new Error(result.error||'The native read failed.');error.detail=result.detail;throw error;}
    if(result.schema!=='fa-dashboard/v1'||result.read_only!==true||!['demo','live'].includes(result.mode))throw new Error('Unsupported local transport.');
    if(S.meta&&result.mode!==S.meta.mode)throw new Error('Data source changed; restart the local workspace.');
    return current()?result:null;
  });
  queue=task;return task;
}
function checkBook(event){snapshot(event);if(S.meta&&event.book!==S.meta.book.book)throw new Error('A report names a different book.');}
function panel(title,subtitle,content,action,cls=''){
  return el('section',{class:'panel '+cls},el('div',{class:'panel-head'},el('div',{},el('h2',{},title),subtitle?el('p',{},subtitle):null),action),content);
}
function note(text){return el('p',{class:'scope-note'},icon('help'),text);}
function empty(title,message,action,symbol='scope'){
  return el('section',{class:'empty-panel'},icon(symbol),el('h2',{},title),el('p',{},message),action);
}
function loading(title='Reading the native snapshot'){
  return el('div',{class:'loading-panel'},el('span',{class:'spinner','aria-hidden':'true'}),el('h2',{},title),el('p',{},'Exact results appear after the native read completes.'));
}
function errorPanel(error,retry){
  return el('div',{class:'error-panel',role:'alert'},el('strong',{},error.message),error.detail?.message?el('p',{},error.detail.message):null,
    error.detail?.fix?el('p',{},'Native guidance: ',error.detail.fix):null,
    el('p',{},'No sample data or empty success was substituted.'),retry?button('Retry selection',retry,'button','refresh'):null);
}
function content(...nodes){graphCleanup();graphCleanup=()=>{};set('#content',...nodes);$('#content').classList.remove('view-enter');void $('#content').offsetWidth;$('#content').classList.add('view-enter');}
function pin(label,scope){set('#snapshot-status',el('span',{class:'status-dot'}),label);$('#snapshot-status').classList.add('is-pinned');S.scope=scope;}
function discard(){
  mainGate.invalidate();spotlightGate.invalidate();detailGate.invalidate();S.result=null;S.scope=null;S.entryFocus=null;
  $('#inspector').close();$('#snapshot-status').classList.remove('is-pinned');set('#snapshot-status',el('span',{class:'status-dot'}),'Selection changed · not yet applied');
  content(empty('Ready for a new perspective.','Apply this selection to read a fresh, explicitly scoped result.',button('Apply selection',loadView,'button primary','arrow')));
}
function updateHeader(){
  const [name,title,subtitle]=names[S.view];$('#crumb-view').textContent=name;$('#page-title').textContent=title;$('#page-subtitle').textContent=subtitle;
  $('#page-eyebrow').textContent=S.view==='compare'?'TWO TIMES. ONE JOURNAL.':S.view==='graph'?'THE LEDGER IS A GRAPH':'THE LEDGER WORKBENCH';
  document.querySelectorAll('[data-view]').forEach(node=>node.setAttribute('aria-current',(node.dataset.view===S.view||(S.view==='accounts'&&node.dataset.view==='overview'))?'page':'false'));
  renderScope();
}
function navigate(view){
  if(!names[view])return;
  mainGate.invalidate();spotlightGate.invalidate();detailGate.invalidate();$('#inspector').close();S.result=null;S.scope=null;S.view=view;
  history.replaceState(null,'',location.pathname+'#'+view);updateHeader();if(S.meta)loadView();
}
function field(label,key,options={}){
  const labelNode=el('label',{class:'scope-field'},el('span',{},label));
  let control;
  if(options.values){control=el('select',{'aria-label':label},...options.values.map(([value,title])=>el('option',{value},title)));}
  else control=el('input',{'aria-label':label,type:options.type||'text',class:options.class||'',spellcheck:'false',autocomplete:'off',list:options.list,placeholder:options.placeholder});
  control.value=S[key];
  control.addEventListener(options.values?'change':'input',()=>{S[key]=control.value;discard();});
  labelNode.append(control);return labelNode;
}
function renderScope(){
  const form=$('#scope-form');form.hidden=['health','periods'].includes(S.view);if(form.hidden)return;
  const periods=S.meta?body(S.meta.periods).periods:[];
  const units=S.overview?[...new Set(stockRows(S.overview.stock).map(row=>row.unit))]:S.unit?[S.unit]:[];
  if(S.unit&&!units.includes(S.unit))units.push(S.unit);
  const knownLabel=S.view==='compare'?'Snapshot B':'As known at';
  const common=[field('Native unit','unit',{values:units.map(u=>[u,u])}),field(knownLabel,'known',{class:'seq',placeholder:'HEAD'})];
  let fields;
  if(S.view==='ledger')fields=[field('Account','account',{class:'account-input',list:'account-options'}),field('From','from',{type:'date'}),field('Through','to',{type:'date'}),...common];
  else if(S.view==='aging')fields=[field('Account','account',{class:'account-input',list:'account-options'}),field('As of','to',{type:'date'}),...common,field('Day bands','buckets',{class:'seq'})];
  else fields=[...(S.view==='graph'?[field('Account','account',{class:'account-input',list:'account-options'})]:[]),field('Effective period','period',{values:periods.map(p=>[p.code,p.code])}),
    ...(S.view==='compare'?[field('Snapshot A','before',{class:'seq'})]:[]),...common];
  const options=el('datalist',{id:'account-options'});
  const seen=new Set();for(const row of S.overview?body(S.overview.stock).rows:[]){if(!seen.has(row.code)){options.append(el('option',{value:row.code},row.name));seen.add(row.code);}}
  set('#scope-fields',...fields,options);
  $('#apply-button').textContent=S.view==='compare'?'Compare snapshots ↗':'Apply selection ↗';
}
async function boot(){
  const current=bootGate.ticket();mainGate.invalidate();spotlightGate.invalidate();S.overview=null;S.result=null;S.scope=null;
  content(loading('Opening the local workbench'));$('#inspector').close();
  try{
    const meta=await api('bootstrap',{},current);if(!meta)return;
    checkBook(meta.book);snapshot(meta.periods);if(meta.periods.book!==meta.book.book)throw new Error('Bootstrap book identities differ.');
    S.meta=meta;$('#book-title').textContent=meta.title;$('#book-title').title=meta.title;$('.book-initial').textContent=meta.title.slice(0,1).toUpperCase();
    $('#book-subtitle').textContent=meta.mode==='demo'?'Synthetic preview':'Local owner session';$('#demo-banner').hidden=meta.mode!=='demo';
    const periods=body(meta.periods).periods;if(!Array.isArray(periods))throw new Error('Missing fiscal calendar.');
    if(!periods.some(p=>p.code===S.period))S.period=(periods.find(p=>p.state.toLowerCase()==='open')||periods.at(-1))?.code||'';
    S.unit=S.unit||body(meta.book).base_unit;
    if(S.known==='HEAD')S.known=at(meta.book);
    if(!S.before)S.before=String(sequence(S.known)>0n?sequence(S.known)-1n:0n);
    if(S.period){
      const overview=await api('overview',{period:S.period,known_at:S.known},current);if(!overview)return;
      checkBook(overview.stock);snapshot(overview.activity,at(overview.stock));stockRows(overview.stock);stockRows(overview.activity);
      S.overview=overview;S.known=overview.known_at;
      S.account=S.account||stockRows(overview.stock).find(r=>r.unit===S.unit)?.code||'';
      const period=periods.find(p=>p.code===S.period);S.from=S.from||period.start;S.to=S.to||body(overview.stock).effective_through;
    }
    updateHeader();await loadView();
  }catch(error){if(current())content(errorPanel(error,boot));}
}
async function overviewFor(selection,current){
  if(S.overview&&body(S.overview.stock).periods[0]===selection.period&&at(S.overview.stock)===selection.known)return S.overview;
  const result=await api('overview',{period:selection.period,known_at:selection.known},current);if(!result)return null;
  checkBook(result.stock);snapshot(result.stock,selection.known);snapshot(result.activity,at(result.stock));stockRows(result.stock);stockRows(result.activity);
  if(body(result.stock).activity!==false||body(result.activity).activity!==true)throw new Error('Native stock/activity modes differ from the selection.');
  S.overview=result;return result;
}
async function loadView(){
  if(!S.meta)return;
  const current=mainGate.ticket();spotlightGate.invalidate();detailGate.invalidate();S.result=null;S.scope=null;
  const selection=Object.freeze({...S,meta:undefined,overview:undefined,scope:undefined,result:undefined});
  content(loading(S.view==='compare'?'Reading both recorded snapshots':S.view==='graph'?'Following the native references':'Reading the native snapshot'));
  $('#content').setAttribute('aria-busy','true');
  try{
    if(!['periods','health'].includes(selection.view)&&selection.known!=='HEAD')sequence(selection.known);
    if(selection.view==='overview'||selection.view==='accounts'){
      if(!selection.period){content(empty('This book has no fiscal periods.','Create periods with the native CLI, then refresh this workspace.'));return;}
      const result=await overviewFor(selection,current);if(!result)return;
      S.known=result.known_at;S.result={kind:selection.view,value:result,selection};pin(`Snapshot #${result.known_at} · fixed recorded prefix`,{book:result.stock.book,period:selection.period,known_at:result.known_at,unit:selection.unit,kind:'native stock and period activity'});renderScope();
      if(selection.view==='overview')renderOverview(result,selection,current);else renderAccounts(result,selection);
    }else if(selection.view==='ledger'){
      const req={account:selection.account,unit:selection.unit,from:selection.from,to:selection.to,known_at:selection.known};
      const result=await api('ledger',req,current);if(!result)return;checkBook(result.report);const model=ledgerModel(result.report,req);
      S.known=at(result.report);S.result={kind:'ledger',value:result,selection:req};pin(`Snapshot #${S.known} · effective ${req.from} — ${req.to}`,{book:result.report.book,...req,known_at:S.known,kind:'general ledger'});renderScope();renderLedger(result,model,req);
    }else if(selection.view==='aging'){
      const req={account:selection.account,as_of:selection.to,known_at:selection.known,buckets:selection.buckets};
      const result=await api('aging',req,current);if(!result)return;checkBook(result.report);snapshot(result.report,req.known_at);
      const model=agingModel(result.report,result.reconciliation,selection.unit);
      S.known=at(result.report);S.result={kind:'aging',value:result,selection:req};pin(`Snapshot #${S.known} · effective through ${req.as_of}`,{book:result.report.book,...req,known_at:S.known,unit:selection.unit,kind:'effective-date aging'});renderScope();renderAging(result,model,selection.unit);
    }else if(selection.view==='compare'){
      const req={period:selection.period,before:selection.before,after:selection.known};sequence(req.before);
      const result=await api('compare',req,current);if(!result)return;checkBook(result.before);checkBook(result.after);const model=comparisonModel(result,req,selection.unit);
      S.known=model.afterAt;S.result={kind:'compare',value:result,selection:req};pin(`#${model.beforeAt} → #${model.afterAt} · effective scope unchanged`,{book:model.book,period:model.period,before:model.beforeAt,after:model.afterAt,effective_through:model.effectiveThrough,unit:selection.unit,kind:result.scope});renderScope();renderCompare(result,model);
    }else if(selection.view==='graph'){
      let graph;
      if(S.entryFocus){graph=entryGraph(S.entryFocus);pin(`Current inspection · ${graph.observed}`,{book:graph.book,entry_at:graph.knownAt,evidence_at:graph.evidenceAt,kind:'current entry relationships'});}
      else{const result=await api('account',{account:selection.account,period:selection.period,known_at:selection.known},current);if(!result)return;checkBook(result.report);snapshot(result.report,selection.known);graph=accountGraph(result.report,selection.unit);S.known=graph.knownAt;
        pin(`Snapshot #${graph.knownAt} · ${selection.account} · ${selection.period}`,{book:graph.book,account:selection.account,period:selection.period,known_at:graph.knownAt,unit:selection.unit,kind:'account contribution relationships'});}
      S.result={kind:'graph',value:graph,selection};renderScope();renderGraph(graph);
    }else if(selection.view==='periods'){
      pin(`Calendar metadata observed at #${at(S.meta.periods)}`,{book:S.meta.periods.book,known_at:at(S.meta.periods),kind:'current calendar metadata'});renderPeriods();
    }else if(selection.view==='health'){
      const result=await api('health',{},current);if(!result)return;checkBook(result.report);S.result={kind:'health',value:result};pin(`Native triage observed at #${at(result.report)}`,{book:result.report.book,known_at:at(result.report),kind:'native triage, not a certificate'});renderHealth(result);
    }
    if(current())announce(names[S.view][0]+' loaded.');
  }catch(error){if(current()){S.result=null;S.scope=null;$('#snapshot-status').classList.remove('is-pinned');set('#snapshot-status',el('span',{class:'status-dot'}),'Selection could not be loaded');content(errorPanel(error,loadView));}}
  finally{if(current())$('#content').removeAttribute('aria-busy');}
}
function metric(label,value,subtitle,qualifier,symbol='wallet',cls=''){
  return el('article',{class:'metric '+cls},el('div',{class:'metric-head'},label,el('span',{class:'metric-symbol'},icon(symbol))),
    el('div',{class:'metric-number',title:typeof value==='object'?moneyText(value,true):String(value)},typeof value==='object'?moneyText(value):value),
    el('div',{class:'metric-foot'},el('span',{},subtitle),el('span',{},qualifier)));
}
function renderOverview(result,selection,current){
  const stock=stockRows(result.stock).filter(r=>r.unit===selection.unit),activity=stockRows(result.activity).filter(r=>r.unit===selection.unit),unit=selection.unit;
  const cards=el('section',{class:'metrics','aria-label':'Account-type summaries'},
    metric('Asset accounts',categoryNet(stock,'Asset',unit),'Debit − credit','STOCK · '+unit,'wallet','featured'),
    metric('Liability accounts',categoryNet(stock,'Liability',unit,true),'Credit − debit','STOCK · '+unit,'layers'),
    metric('Revenue accounts',categoryNet(activity,'Revenue',unit,true),'Credit − debit','PERIOD · '+unit,'trend'),
    metric('Expense accounts',categoryNet(activity,'Expense',unit),'Debit − credit','PERIOD · '+unit,'ledger','coral'));
  const chosen=stock.find(row=>row.code===S.account)||stock[0];if(chosen)S.account=chosen.code;
  const select=el('select',{class:'inline-input','aria-label':'Spotlight account'},...stock.map(row=>el('option',{value:row.code},row.code+' · '+row.name)));if(chosen)select.value=chosen.code;
  const chartArea=el('div',{id:'spotlight-chart'},loading('Reading account movement'));
  const trailArea=el('div',{id:'spotlight-trail'},loading('Resolving the evidence trail'));
  const chartPanel=panel('Account spotlight','Daily closing balance · one recorded snapshot',chartArea,select);
  const trailPanel=panel('Behind the balance','Source references, not an attachment count',trailArea,null,'trail-panel');
  const prompt=el('section',{class:'time-prompt'},el('div',{class:'time-symbol'},icon('time')),el('div',{},el('strong',{},'What changed when the ledger learned more?'),
    el('p',{},'Compare two recorded snapshots while keeping the effective period fixed.')),button('Open time lens',()=>navigate('compare'),'button','arrow'));
  const grid=el('div',{class:'split-grid'},chartPanel,trailPanel);
  content(cards,grid,prompt,accountTablePanel(result,selection,false),note('Cards group named account types; they are not classified financial statements. Stock includes opening history. Period activity does not.'));
  select.addEventListener('change',()=>{S.account=select.value;loadSpotlight(S.account,result,selection,current);});
  if(chosen)loadSpotlight(chosen.code,result,selection,current);else{set(chartArea,empty('No account rows in this unit.','Choose another native unit.'));set(trailArea,empty('No graph to infer.','Only references returned by the native report will be drawn.'));}
}
async function loadSpotlight(account,result,selection,parentCurrent){
  const local=spotlightGate.ticket(),current=()=>local()&&parentCurrent()&&S.view==='overview';
  const p=body(S.meta.periods).periods.find(p=>p.code===selection.period);
  const req={account,unit:selection.unit,from:p.start,to:body(result.stock).effective_through,known_at:result.known_at};
  set('#spotlight-chart',loading('Reading '+account));set('#spotlight-trail',loading('Following source references'));
  try{
    const ledger=await api('ledger',req,current);if(!ledger)return;checkBook(ledger.report);const model=ledgerModel(ledger.report,req);
    if(model){set('#spotlight-chart',el('div',{class:'spotlight-numbers'},el('div',{class:'spotlight-value'},moneyText(model.closing),el('small',{},selection.unit)),
        el('div',{class:'movement-summary'},el('strong',{},moneyText(subtract(model.closing,model.opening),true)),'Net movement in this period')),
        balanceChart(model,()=>{S.from=req.from;S.to=req.to;navigate('ledger');}),
        el('div',{class:'panel-foot'},el('span',{},'Native account '+account),button('Explore the ledger',()=>{S.from=req.from;S.to=req.to;navigate('ledger');},'text-link','arrow')));
    }else set('#spotlight-chart',empty('No cell reported.','An absent account/unit cell is not a verified zero.'));
    const detail=await api('account',{account,period:selection.period,known_at:result.known_at},current);if(!detail)return;
    checkBook(detail.report);snapshot(detail.report,result.known_at);const graph=accountGraph(detail.report,selection.unit);
    const docs=graph.nodes.filter(n=>n.kind==='document').length;
    set('#spotlight-trail',miniGraph(graph),el('div',{class:'trail-counts'},...[[graph.totalEntries,'Entries'],[docs,'Shown documents'],[graph.totalContributions,'Period legs']].map(([count,label])=>el('div',{},el('strong',{},count),el('span',{},label)))),
      el('div',{class:'trail-actions'},button('Follow the evidence',()=>{S.entryFocus=null;navigate('graph');},'button primary','graph'),
        el('p',{},graph.omittedEntries?`${graph.omittedEntries} additional entries are outside this bounded preview.`:'Explore actual citations and connected entries. No document content is fetched.')));
  }catch(error){if(current()){set('#spotlight-trail',errorPanel(error,()=>loadSpotlight(account,result,selection,parentCurrent)));if($('#spotlight-chart .loading-panel'))set('#spotlight-chart',errorPanel(error));}}
}
function miniGraph(graph){
  const layout=layoutGraph(graph);layout.step(190);const bounds=graphBounds(layout.nodes);
  const picture=svg('svg',{viewBox:`${bounds.x} ${bounds.y} ${bounds.width} ${bounds.height}`,role:'img','aria-label':`Preview of ${graph.nodes.length} actual reference nodes; open evidence graph for details.`});
  for(const edge of layout.edges)picture.append(svg('line',{x1:edge.source.x,y1:edge.source.y,x2:edge.target.x,y2:edge.target.y,stroke:'var(--line)','stroke-width':4}));
  for(const node of layout.nodes){const color=node.root?'var(--forest)':node.kind==='document'?'var(--purple)':'var(--accent)';picture.append(svg('circle',{cx:node.x,cy:node.y,r:node.root?26:13,fill:color},svg('title',{},node.label+' · '+node.sub)));}
  return el('div',{class:'trail-graphic'},picture);
}
function balanceChart(model,onSelect){
  const width=820,height=256,left=90,right=27,top=24,bottom=35,w=width-left-right,h=height-top-bottom;
  const chart=svg('svg',{class:'balance-chart',viewBox:`0 0 ${width} ${height}`,role:'group','aria-label':'Daily closing balances. Tab to points for exact values; Enter selects a date.'});
  const defs=svg('defs',{},svg('linearGradient',{id:'balance-fill',x1:'0',y1:'0',x2:'0',y2:'1'},svg('stop',{offset:'0%','stop-color':'var(--accent)','stop-opacity':'.16'}),svg('stop',{offset:'100%','stop-color':'var(--accent)','stop-opacity':'.015'})));chart.append(defs);
  const range=subtract(model.max,model.min);
  for(let i=0;i<=3;i++){const y=top+i*h/3;const tick=add(model.min,{...range,n:range.n*BigInt(3-i)/3n});chart.append(svg('line',{x1:left,y1:y,x2:width-right,y2:y,class:'chart-grid'}),svg('text',{x:left-12,y:y+4,'text-anchor':'end'},moneyText(tick)));}
  const points=model.points.map(p=>({...p,cx:left+p.x*w,cy:top+(1-p.y)*h}));
  let path=`M${points[0].cx},${points[0].cy}`;for(const p of points.slice(1))path+=`H${p.cx}V${p.cy}`;
  chart.append(svg('path',{d:path+`L${points.at(-1).cx},${top+h}H${points[0].cx}Z`,class:'chart-fill'}),svg('path',{d:path,class:'chart-line'}));
  const readout=el('div',{class:'chart-readout'},el('span',{},'Daily closing · hover or focus a point'),el('strong',{},moneyText(model.closing,true)));
  const cross=svg('line',{x1:0,x2:0,y1:top,y2:top+h,stroke:'var(--accent)','stroke-width':1,'stroke-dasharray':'3 5',visibility:'hidden'});chart.append(cross);
  for(const p of points){const g=svg('g',{class:'chart-node',tabindex:'0',role:'button','aria-label':`${p.date}: ${p.label}, ${moneyText(p.amount,true)}. Select date.`},
      svg('title',{},`${p.date} · ${p.label}\n${moneyText(p.amount,true)}`),svg('circle',{cx:p.cx,cy:p.cy,r:10,class:'chart-hit'}),svg('circle',{cx:p.cx,cy:p.cy,r:3.3,class:'chart-point'}));
    const reveal=()=>{set(readout,el('span',{},p.date+' · '+p.label),el('strong',{},moneyText(p.amount,true)));cross.setAttribute('x1',p.cx);cross.setAttribute('x2',p.cx);cross.setAttribute('visibility','visible');};
    g.addEventListener('pointerenter',reveal);g.addEventListener('focus',reveal);g.addEventListener('click',()=>onSelect?.(p.date));
    g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onSelect?.(p.date);}});chart.append(g);
  }
  chart.append(svg('text',{x:left,y:height-9},points[0].date),svg('text',{x:width-right,y:height-9,'text-anchor':'end'},points.at(-1).date));
  return el('div',{},el('div',{class:'chart-holder'},chart),readout,el('p',{class:'chart-annotation'},model.sampled?'Bounded daily-point envelope; all movement rows remain in the table.':'Daily closings at this snapshot, not intraday extremes or historical knowledge on each day.'));
}
function typeLabel(type){const known=['asset','liability','equity','revenue','expense'].includes(type.toLowerCase())?type.toLowerCase():'other';return el('span',{class:'type-label'},el('i',{class:'type-dot type-'+known}),type);}
function table(headers,rows,cls=''){
  return el('div',{class:'table-scroll'},el('table',{class:cls},el('thead',{},el('tr',{},...headers.map(h=>el('th',{scope:'col',class:h.numeric?'numeric':''},h.node||h)))),el('tbody',{},...rows)));
}
function pages(rows,renderRow,headers,options={}){
  let page=0;const root=el('div');const pageSize=25;
  const draw=()=>{const count=Math.max(1,Math.ceil(rows.length/pageSize));page=Math.max(0,Math.min(page,count-1));
    const prev=button('',()=>{page--;draw();},'','chevron');prev.setAttribute('aria-label','Previous page');prev.disabled=page===0;prev.firstChild.classList.add('flip');
    const next=button('',()=>{page++;draw();},'','chevron');next.setAttribute('aria-label','Next page');next.disabled=page>=count-1;
    set(root,rows.length?table(headers,rows.slice(page*pageSize,(page+1)*pageSize).map(renderRow),options.class||''):empty('No matching rows.','Clear the filter or choose another selection.'),
      el('div',{class:'panel-foot'},el('span',{},`${rows.length} ${options.label||'rows'}${options.suffix||''}`),el('div',{class:'pagination'},prev,el('span',{},`${page+1} / ${count}`),next)));
  };draw();return root;
}
function accountLink(row,action){return button([el('span',{class:'account-code'},row.code),el('span',{class:'account-name'},row.name),icon('diagonal')],action,'account-link');}
function accountTablePanel(result,selection,full){
  let mode='stock',search='',type='All types',sort='code',direction=1;
  const box=el('div'),host=el('div');
  const source=()=>stockRows(result[mode]).filter(r=>r.unit===selection.unit&&(!search||`${r.code} ${r.name}`.toLowerCase().includes(search))&&(type==='All types'||r.type===type));
  const changeSort=key=>{direction=sort===key?-direction:1;sort=key;draw();};
  const headers=[{node:button('Account',()=>changeSort('code'),'sort-button')},{node:button('Type',()=>changeSort('type'),'sort-button')},
    ...['debits','credits','net'].map(key=>({numeric:true,node:button(key==='net'?'Native net':key[0].toUpperCase()+key.slice(1),()=>changeSort(key),'sort-button')}))];
  const tab=el('div',{class:'tab-bar'},...['stock','activity'].map(kind=>button(kind==='stock'?'Stock balances':'Period activity',()=>{mode=kind;[...tab.children].forEach(n=>n.setAttribute('aria-pressed',n===tab.children[kind==='stock'?0:1]));draw();},'')));
  tab.children[0].setAttribute('aria-pressed','true');tab.children[1].setAttribute('aria-pressed','false');
  const query=el('input',{type:'search','aria-label':'Search accounts',placeholder:'Find an account…',oninput:event=>{search=event.target.value.toLowerCase();draw();}});
  const types=[...new Set(body(result.stock).rows.map(r=>r.type))];
  const filter=el('select',{'aria-label':'Account type',onchange:event=>{type=event.target.value;draw();}},...['All types',...types].map(t=>el('option',{value:t},t)));
  const getRows=()=>source().sort((a,b)=>direction*(['debits','credits','net'].includes(sort)?compare(parseAmount(a[sort]),parseAmount(b[sort])):a[sort].localeCompare(b[sort],'en',{numeric:true})));
  const exportRows=()=>{const fields=['code','name','type','debits','credits','net','debits_pending','credits_pending'];const rows=getRows();
    download('accounts',csv([['mode','book','period','known_at','report_mode','unit',...fields],...rows.map(r=>[S.meta.mode,result.stock.book,selection.period,result.known_at,mode,selection.unit,...fields.map(f=>r[f])])]))};
  function draw(){const rows=getRows();const renderRow=row=>el('tr',{},el('td',{},accountLink(row,()=>openAccount(row.code,selection.period,result.known_at))),el('td',{},typeLabel(row.type)),...['debits','credits','net'].map(key=>el('td',{class:'numeric'},amount(row[key]))));
    set(host,full?pages(rows,renderRow,headers,{label:'account / unit rows'}):table(headers,rows.slice(0,6).map(renderRow)));
  }
  box.append(el('div',{class:'table-tools'},full?el('div',{},el('div',{class:'search-box'},icon('search'),query),filter):tab,full?button('Export view',exportRows,'button compact','down'):button('Browse all accounts',()=>navigate('accounts'),'text-link','arrow')),host);
  if(full)box.prepend(el('div',{class:'table-tools'},tab));
  else box.append(el('div',{class:'panel-foot'},tag(body(result.stock).balanced?'Native debits = credits':'Native balance verdict is red',body(result.stock).balanced?'good':'bad',body(result.stock).balanced?'check':'warning'),el('span',{},'No report certificate requested')));
  draw();return panel('Accounts, without the guesswork',`${selection.period} · ${selection.unit} · commit #${result.known_at}`,box);
}
function renderAccounts(result,selection){content(accountTablePanel(result,selection,true),note('Native net sign conventions are preserved. The inspector explains period movement, not cumulative opening stock.'))}
function csv(rows){return '\ufeff'+rows.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';}
function download(kind,text){
  const url=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'}));const link=el('a',{href:url,download:`franken-${S.meta.mode}-${kind}.csv`});
  document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);toast('Exported the displayed scope with exact amount strings.');
}
async function copy(text){try{await navigator.clipboard.writeText(text);toast('Copied. Keep this book reference private.');}catch{inspect('Copy this reference',el('pre',{class:'native-json'},text));}}

function renderLedger(result,model,selection){
  if(!model){content(empty('No account/unit cell was reported.','An absent cell is not a verified zero. Try another explicit account or native unit.'));return;}
  const b=body(result.report);let search='',date='';const rowsHost=el('div');
  const cards=el('section',{class:'metrics'},metric('Opening stock',model.opening,'Before selected movements',selection.unit,'wallet'),
    metric('Posted debits',model.debits,'Selected interval',selection.unit,'trend'),metric('Posted credits',model.credits,'Selected interval',selection.unit,'layers','coral'),
    metric('Closing stock',model.closing,'Through inclusive cutoff',selection.unit,'wallet','featured'));
  const currentRows=()=>model.lines.filter(row=>(!date||row.effective_date===date)&&`${row.effective_date} ${row.class} ${row.entry_digest} ${row.recorded_at}`.toLowerCase().includes(search));
  const query=el('input',{type:'search','aria-label':'Filter ledger movements',placeholder:'Find a date, class, or digest…',oninput:event=>{search=event.target.value.toLowerCase();draw();}});
  const filterStatus=el('span',{class:'table-note'},'All movement dates');
  const chart=balanceChart(model,selected=>{date=selected;filterStatus.textContent='Filtered to '+date;draw();announce('Movement table filtered to '+date);});
  function draw(){set(rowsHost,pages(currentRows(),row=>el('tr',{},el('td',{},el('div',{class:'account-name'},row.effective_date,el('small',{},'Recorded #'+row.recorded_at))),
    el('td',{},button([icon('document'),short(row.entry_digest,16)+' · L'+row.leg_index],()=>inspect('Posted movement',el('div',{},tag('Exact native leg reference'),metadata([
      ['Entry digest',row.entry_digest],['Leg ordinal',row.leg_index],['Recorded at','#'+row.recorded_at],['Effective date',row.effective_date],['Account',row.account],['Unit',row.unit],
      ['Posted debits',row.debits],['Posted credits',row.credits],['Running balance',row.running_balance]]),note('This is a 64-hex digest, not a 32-hex entry handle. The dashboard does not invent a vertex reference.'),
      button('Copy exact leg reference',()=>copy(JSON.stringify({book:result.report.book,known_at:b.known_at,entry_digest:row.entry_digest,leg_index:row.leg_index},null,2)),'button','copy'))),'digest-button')),
    el('td',{},tag(row.class)),...['debits','credits','running_balance'].map(key=>el('td',{class:'numeric'},amount(row[key])))),
      ['Effective / recorded','Entry / leg','Class',{node:'Debits',numeric:true},{node:'Credits',numeric:true},{node:'Running balance',numeric:true}],{label:'visible movements',suffix:' · running balances retain full scope'}));}
  const tools=el('div',{class:'table-tools'},el('div',{},el('div',{class:'search-box'},icon('search'),query),filterStatus),button('Clear date filter',()=>{date='';filterStatus.textContent='All movement dates';draw();},'text-link'));
  content(cards,panel(model.cell.account+' · '+model.cell.name,'Daily closing balances · debit minus credit',chart,
      tag('#'+b.known_at,'','lock')),el('div',{class:'flow-rule'}),panel('Every posted movement','Native order and complete leg references. Opposing movements remain visible.',el('div',{},tools,rowsHost),
      button('Export view',()=>download('general-ledger',reportCsv(S.meta.mode,result.report.book,'ledger',b,selection.unit,currentRows())),'button compact','down')),
    note('Daily closing balances are computed at the selected recorded snapshot, not what was known on each movement’s day. This is not a classified cash-flow statement.'));
  draw();
}
function renderAging(result,model,unit){
  const b=body(result.report);let search='',band='',side='All sides',sort='oldest';const rowsHost=el('div');
  const oldest=model.items.reduce((max,item)=>BigInt(item.age_days)>max?BigInt(item.age_days):max,0n);
  const cards=el('section',{class:'metrics'},metric('Debit open amounts',model.debits,'Gross amounts, not netted',unit,'wallet','featured'),
    metric('Credit open amounts',model.credits,'Separate credit column',unit,'layers','coral'),metric('Open items',String(model.items.length),'In this native unit','SELECTED SCOPE','document'),
    metric('Oldest effective age',model.items.length?oldest+' days':'—','Not a contractual due date','AGE, NOT OVERDUE','aging'));
  const okay=model.reconciled&&!!model.check,unknown=!model.check;
  const rec=el('section',{class:'reconciliation '+(!model.reconciled?'bad':unknown?'neutral':'')},icon(okay?'shield':unknown?'help':'warning'),
    el('div',{},el('strong',{},!model.reconciled?'Native reconciliation is red':unknown?'Selected unit was not reported in reconciliation':'Selected unit ties to its control balance'),
      el('p',{},S.meta.mode==='demo'?'Synthetic result only. No native accounting check was performed.':!model.reconciled?'At least one native-unit reconciliation failed; changing the display unit does not clear that failure.':'Open amounts and control balances share recorded snapshot #'+b.known_at+'.')),
    el('span',{},model.check?'Difference: '+moneyText(model.check.difference,true):'Unreported ≠ verified zero'));
  let max=zero(unit);for(const item of model.bands)for(const value of [item.debits,item.credits])if(compare(value,max)>0)max=value;
  const bandButtons=model.bands.map((item,i)=>{
    const bars=svg('svg',{viewBox:'0 0 200 28','aria-hidden':'true'},svg('rect',{x:0,y:1,width:ratio(item.debits,max,200),height:8,rx:3,fill:'var(--accent)'}),
      svg('rect',{x:0,y:16,width:ratio(item.credits,max,200),height:8,rx:3,fill:'var(--coral)'}));
    const node=button([el('strong',{},bandLabel(item)),el('div',{class:'aging-band-line'},el('span',{},'Debit'),el('span',{class:'numeric'},moneyText(item.debits))),
      el('div',{class:'aging-band-line'},el('span',{},'Credit'),el('span',{class:'numeric'},moneyText(item.credits))),bars,el('small',{},item.count+' open items')],()=>{
        band=band===String(i)?'':String(i);bandButtons.forEach((n,j)=>n.setAttribute('aria-pressed',band===String(j)));draw();},'aging-band');node.setAttribute('aria-pressed','false');return node;
  });
  const currentRows=()=>model.items.filter(item=>(!band||item.bucket===band)&&(side==='All sides'||item.side===side)&&`${item.entry} ${item.effective_date} ${item.recorded_at}`.toLowerCase().includes(search)).sort((a,b)=>{
    if(sort==='amount')return compare(parseAmount(b.open),parseAmount(a.open));
    return BigInt(a.age_days)>BigInt(b.age_days)?-1:BigInt(a.age_days)<BigInt(b.age_days)?1:a.entry.localeCompare(b.entry);
  });
  function draw(){set(rowsHost,pages(currentRows(),item=>el('tr',{},el('td',{},button([short(item.entry,15),el('small',{},'Leg '+item.ordinal+' · #'+item.recorded_at)],()=>openEntry(item.entry),'entry-link')),
      el('td',{},el('div',{class:'account-name'},item.effective_date,el('small',{},item.age_days+' effective days'))),el('td',{},tag(item.side,item.side==='Credit'?'coral':'good')),
      ...['original','applied','applied_out','open'].map(key=>el('td',{class:'numeric'},amount(item[key])))),
      ['Entry / leg','Effective age','Side',{node:'Original',numeric:true},{node:'Applied in',numeric:true},{node:'Applied out',numeric:true},{node:'Remaining',numeric:true}],{label:'matching items',suffix:' · summary cards retain full scope'}));}
  const query=el('input',{type:'search',placeholder:'Find an entry or date…','aria-label':'Filter open items',oninput:e=>{search=e.target.value.toLowerCase();draw();}});
  const sideSelect=el('select',{'aria-label':'Open-item side',onchange:e=>{side=e.target.value;draw();}},...['All sides','Debit','Credit'].map(t=>el('option',{value:t},t)));
  const sortSelect=el('select',{'aria-label':'Open-item order',onchange:e=>{sort=e.target.value;draw();}},el('option',{value:'oldest'},'Oldest first'),el('option',{value:'amount'},'Largest open amount'));
  content(cards,rec,panel('An age, not an assumption','Select a band to filter items. Ages are measured from effective dates.',el('div',{class:'aging-band-grid'},...bandButtons),
      el('div',{class:'legend'},el('span',{},el('i',{class:'swatch'}),'Debit'),el('span',{},el('i',{class:'swatch coral'}),'Credit'))),el('div',{class:'flow-rule'}),
    panel('The open-item detail','Original amounts, applications, and what remains.',el('div',{},el('div',{class:'table-tools'},el('div',{},el('div',{class:'search-box'},icon('search'),query),sideSelect,sortSelect),
      button('Clear band',()=>{band='';bandButtons.forEach(n=>n.setAttribute('aria-pressed','false'));draw();},'text-link')),rowsHost),button('Export view',()=>download('aging',reportCsv(S.meta.mode,result.report.book,'aging',b,unit,currentRows())),'button compact','down')),
    note('Entry inspection uses current native entry/evidence APIs, labeled with their own observation sequences. It does not move this historical aging snapshot.'));
  draw();
}
function renderCompare(result,model){
  let onlyChanged=true,search='';const host=el('div');
  const snapshotCard=(letter,atValue,verdict)=>el('article',{class:'snapshot-card '+letter.toLowerCase()},el('div',{class:'snapshot-card-head'},el('span',{class:'snapshot-letter'},letter),tag('Fixed snapshot','','lock')),
    el('div',{class:'snapshot-value'},'#'+atValue),el('p',{},model.period+' · through '+model.effectiveThrough),el('div',{class:'detail-tags'},tag(verdict?'Native balance: equal':'Native balance: red',verdict?'good':'bad')));
  const pair=el('section',{class:'snapshot-pair'},snapshotCard('A',model.beforeAt,model.balancedBefore),el('div',{class:'snapshot-connector'},icon('arrow')),snapshotCard('B',model.afterAt,model.balancedAfter));
  const summary=el('div',{class:'comparison-summary'},...[[model.changed,'changed rows'],[model.rows.filter(r=>r.status==='added').length,'newly reported'],[model.rows.filter(r=>r.metadataChanged).length,'metadata changes'],[model.rows.length-model.changed,'unchanged']].map(([n,label])=>el('span',{},el('strong',{},n),label)));
  const changes=model.rows.filter(r=>r.delta.n!==0n).sort((a,b)=>compare(abs(b.delta),abs(a.delta))).slice(0,8);
  const chart=changes.length?deltaChart(changes,row=>openComparisonRow(row,model)):
    empty('No net balance movement.','Gross columns, pending amounts, or metadata can still differ. The comparison table retains those changes.',null,'time');
  const rows=()=>model.rows.filter(r=>(!onlyChanged||r.status!=='unchanged')&&`${r.code} ${r.name} ${r.status}`.toLowerCase().includes(search));
  const statusLabel={added:'New in report',removed:'Absent in B',changed:'Amounts changed',metadata:'Metadata changed',unchanged:'Unchanged'};
  function draw(){set(host,pages(rows(),r=>el('tr',{},el('td',{},accountLink(r,()=>openComparisonRow(r,model))),el('td',{},tag(statusLabel[r.status],r.status==='unchanged'?'':r.status==='removed'?'coral':'good')),
      el('td',{class:'numeric'},r.before?amount(r.before.balance):el('span',{title:'This account/unit row is not present in snapshot A.'},'—')),
      el('td',{class:'numeric'},r.after?amount(r.after.balance):el('span',{title:'This account/unit row is not present in snapshot B.'},'—')),
      el('td',{class:'numeric'},el('span',{class:'delta-value '+(r.delta.n<0n?'negative':r.delta.n>0n?'positive':'')},r.delta.n>0n?'+':'',moneyText(r.delta)),
        r.delta.n===0n&&r.moneyChanged?el('small',{class:'row-meta'},'Gross or pending columns changed'):r.metadataChanged?el('small',{class:'row-meta'},'Metadata changed'):null)),
      ['Account','Difference',{node:'A · debit − credit',numeric:true},{node:'B · debit − credit',numeric:true},{node:'B − A',numeric:true}],{class:'comparison-table',label:'comparison rows'}));}
  const toggle=el('div',{class:'tab-bar'},...['Changes only','All rows'].map((name,i)=>button(name,()=>{onlyChanged=i===0;[...toggle.children].forEach((n,j)=>n.setAttribute('aria-pressed',i===j));draw();},'')));
  toggle.children[0].setAttribute('aria-pressed','true');toggle.children[1].setAttribute('aria-pressed','false');
  const query=el('input',{type:'search','aria-label':'Filter comparison rows',placeholder:'Find a changed account…',oninput:e=>{search=e.target.value.toLowerCase();draw();}});
  content(pair,summary,panel('The difference, account by account','Signed B − A · debit-minus-credit balances · '+S.unit,el('div',{class:'panel-body'},chart),tag('Effective scope fixed','','calendar')),
    el('div',{class:'flow-rule'}),panel('Two snapshots. Nothing overwritten.','Select a row for its exact gross, pending, and metadata differences.',el('div',{},el('div',{class:'table-tools'},toggle,el('div',{class:'search-box'},icon('search'),query)),host),
      button('Export comparison',()=>download('snapshot-comparison',comparisonCsv(model,S.meta.mode,rows())),'button compact','down')),
    note('This is a difference between report rows, not causal attribution or a signed restatement. Missing rows are shown as absent; only the displayed difference treats an absent row as zero. Codes identify report rows, not proof of account identity continuity.'));
  draw();
}
function deltaChart(rows,onSelect){
  const max=rows.reduce((a,r)=>compare(abs(r.delta),a)>0?abs(r.delta):a,zero(rows[0].unit));
  const height=rows.length*50+24,chart=svg('svg',{class:'change-chart',viewBox:`0 0 940 ${height}`,role:'group','aria-label':'Signed account-row differences between snapshot A and B.'});
  chart.append(svg('line',{x1:580,x2:580,y1:5,y2:height-10,class:'chart-grid'}));
  rows.forEach((r,i)=>{const y=30+i*50,w=ratio(r.delta,max,204),negative=r.delta.n<0n;
    const group=svg('g',{tabindex:'0',role:'button','aria-label':`${r.code} ${r.name}. Difference ${moneyText(r.delta,true)}. Inspect row.`},
      svg('title',{},`${r.code} · ${r.name}\nB − A: ${moneyText(r.delta,true)}`),svg('text',{x:2,y:y-3,fill:'var(--ink)','font-size':12},r.name),svg('text',{x:2,y:y+13,'font-size':9},r.code),
      svg('rect',{x:negative?580-w:580,y:y-9,width:w,height:14,rx:4,class:negative?'change-negative':'change-positive'}),
      svg('text',{x:936,y:y+2,'text-anchor':'end'},(r.delta.n>0n?'+':'')+moneyText(r.delta)));
    group.addEventListener('click',()=>onSelect(r));group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onSelect(r);}});chart.append(group);
  });return chart;
}
function openComparisonRow(row,model){
  const columns=['debits','credits','debits_pending','credits_pending'];
  inspect(row.code+' · '+row.name,el('div',{},el('div',{class:'detail-tags'},tag('A #'+model.beforeAt),tag('B #'+model.afterAt),tag(row.unit)),
    table(['Column',{node:'Snapshot A',numeric:true},{node:'Snapshot B',numeric:true},{node:'B − A',numeric:true}],columns.map(key=>el('tr',{},el('td',{},key.replaceAll('_',' ')),
      el('td',{class:'numeric'},row.before?amount(row.before.values[key]):'—'),el('td',{class:'numeric'},row.after?amount(row.after.values[key]):'—'),el('td',{class:'numeric'},amount(row.deltaColumns[key]))))),
    metadata([['Name in A',row.before?.name||'Not reported'],['Name in B',row.after?.name||'Not reported'],['Type in A',row.before?.type||'Not reported'],['Type in B',row.after?.type||'Not reported']]),
    note('Period contributions are a narrower scope than stock differences, which can include opening history and visibility changes. The next action is period detail, not an attribution proof.'),
    button('Inspect '+(row.after?'B':'A')+' period detail',()=>openAccount(row.code,model.period,row.after?model.afterAt:model.beforeAt),'button primary','arrow')));
}
function renderGraph(graph){
  $('#scope-form').hidden=graph.kind==='entry';
  const stage=el('div',{class:'graph-stage'}),inspector=el('aside',{class:'graph-inspector','aria-label':'Selected graph object'}),list=el('div',{class:'graph-list',hidden:true});
  const toolbar=el('div',{class:'graph-toolbar'}),searchWrap=el('div',{class:'graph-search'});
  const canvas=el('div',{class:'graph-main'},toolbar,searchWrap,stage,list,el('div',{class:'graph-key'},
    el('span',{},el('i',{}),'Account'),el('span',{},el('i',{class:'entry-key'}),'Entry'),el('span',{},el('i',{class:'document-key'}),'Document'),
    el('span',{},graph.nodes.length+' shown objects · '+graph.edges.length+' relationships')));
  const layout=layoutGraph(graph);layout.step(140);
  let selected=null,type='all',term='',disposed=false,frame=0,drag=null,wasDragged=false;
  let view=graphBounds(layout.nodes);
  const root=svg('svg',{class:'graph-svg',viewBox:`${view.x} ${view.y} ${view.width} ${view.height}`,role:'group','aria-label':'Interactive evidence graph. Drag nodes to pin, drag background to pan. Zoom controls below. Tab through nodes to inspect.'});
  const edgeLayer=svg('g'),nodeLayer=svg('g');root.append(edgeLayer,nodeLayer);stage.append(root);
  const edgeNodes=layout.edges.map(edge=>{const n=svg('path',{class:'graph-edge '+edge.relation.replaceAll(' ','-')},svg('title',{},edge.relation));edgeLayer.append(n);return n;});
  const nodeNodes=layout.nodes.map((node,i)=>{
    const card=svg('g',{class:'graph-node '+node.kind+(node.root?' root':''),tabindex:'0',role:'button','data-node':i,'aria-label':`${node.kind}: ${node.label}, ${node.sub}. Inspect object.`},
      svg('title',{},`${node.kind} · ${node.label}\n${node.id}`),svg('rect',{x:-76,y:-30,width:152,height:60,rx:10}),
      svg('rect',{x:-63,y:-14,width:28,height:28,rx:7,class:'node-icon-bg'}),svg('text',{x:-49,y:5,'text-anchor':'middle',class:'node-type-mark'},node.kind==='document'?'D':node.kind==='account'?'A':node.kind==='principal'?'P':'E'),
      svg('text',{x:-24,y:-3,class:'node-label'},short(node.label,20)),svg('text',{x:-24,y:13,class:'node-sub'},short(node.sub,22)));
    card.addEventListener('click',()=>{if(!wasDragged)selectNode(node);});card.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();selectNode(node);}});
    nodeLayer.append(card);return card;
  });
  function draw(){
    layout.edges.forEach((edge,i)=>{edgeNodes[i].setAttribute('d',`M${edge.source.x} ${edge.source.y}L${edge.target.x} ${edge.target.y}`);});
    layout.nodes.forEach((node,i)=>nodeNodes[i].setAttribute('transform',`translate(${node.x} ${node.y})`));
  }
  function camera(){root.setAttribute('viewBox',`${view.x} ${view.y} ${view.width} ${view.height}`);}
  function fit(){view=graphBounds(layout.nodes);camera();}
  function zoom(factor){const width=Math.max(240,Math.min(6000,view.width*factor)),height=view.height*width/view.width;view={x:view.x+(view.width-width)/2,y:view.y+(view.height-height)/2,width,height};camera();}
  function selectedSet(){const ids=new Set();if(selected){ids.add(selected.id);for(const edge of layout.edges){if(edge.source.id===selected.id)ids.add(edge.target.id);if(edge.target.id===selected.id)ids.add(edge.source.id);}}return ids;}
  function highlights(){const neighborhood=selectedSet();layout.nodes.forEach((node,i)=>{const match=(type==='all'||node.kind===type)&&`${node.label} ${node.sub} ${node.id}`.toLowerCase().includes(term);nodeNodes[i].classList.toggle('dimmed',!match||(selected&&!neighborhood.has(node.id)));nodeNodes[i].classList.toggle('selected',node===selected);});
    layout.edges.forEach((edge,i)=>{const connected=selected&&(edge.source===selected||edge.target===selected);edgeNodes[i].classList.toggle('selected',!!connected);edgeNodes[i].classList.toggle('dimmed',!!selected&&!connected);});
    set(list,...layout.nodes.filter(node=>(type==='all'||node.kind===type)&&`${node.label} ${node.sub} ${node.id}`.toLowerCase().includes(term)).map(node=>button([el('span',{},node.label,el('small',{},' · '+node.sub)),tag(node.kind)],()=>selectNode(node),'')));
  }
  function selectNode(node){selected=node;highlights();renderObject(inspector,node,graph);announce('Selected '+node.kind+' '+node.label);}
  const filters=el('div',{},...['all','entry','document','account'].map(kind=>{
    const n=button(({all:'All objects',entry:'Entries',document:'Documents',account:'Accounts'})[kind],()=>{type=kind;[...filters.children].forEach(x=>x.setAttribute('aria-pressed',x===n));highlights();},'tag');n.setAttribute('aria-pressed',kind==='all');return n;
  }));
  const tabs=el('div',{class:'tab-bar'},button([icon('graph'),'Graph'],()=>{stage.hidden=false;list.hidden=true;tabs.children[0].setAttribute('aria-pressed','true');tabs.children[1].setAttribute('aria-pressed','false');},''),
    button([icon('list'),'List'],()=>{stage.hidden=true;list.hidden=false;tabs.children[0].setAttribute('aria-pressed','false');tabs.children[1].setAttribute('aria-pressed','true');},''));tabs.children[0].setAttribute('aria-pressed','true');tabs.children[1].setAttribute('aria-pressed','false');
  toolbar.append(filters,button('Clear focus',()=>{selected=null;highlights();renderObject(inspector,layout.nodes.find(n=>n.root)||layout.nodes[0],graph);},'text-link'),tabs);
  const search=el('input',{type:'search','aria-label':'Find a graph object',placeholder:'Find an object or reference…',oninput:e=>{term=e.target.value.toLowerCase();highlights();}});searchWrap.append(el('div',{class:'search-box'},icon('search'),search));
  const zoomIn=button('',()=>zoom(.8),'icon-button','plus');zoomIn.setAttribute('aria-label','Zoom in');
  const zoomOut=button('',()=>zoom(1.25),'icon-button','minus');zoomOut.setAttribute('aria-label','Zoom out');
  const fitButton=button('',fit,'icon-button','fit');fitButton.setAttribute('aria-label','Fit graph');
  const reset=button('',()=>renderGraph(graph),'icon-button','refresh');reset.setAttribute('aria-label','Reset graph layout and pins');
  stage.append(el('div',{class:'graph-controls'},zoomIn,zoomOut,fitButton,reset),el('div',{class:'graph-hint'},'Drag to pin · background to pan'));
  const point=event=>{const matrix=root.getScreenCTM();if(!matrix)return {x:0,y:0};const p=new DOMPoint(event.clientX,event.clientY).matrixTransform(matrix.inverse());return {x:p.x,y:p.y};};
  root.addEventListener('pointerdown',event=>{
    if(event.button!==0)return;
    const target=event.target.closest('[data-node]'),node=target?layout.nodes[Number(target.dataset.node)]:null;
    const p=point(event);drag={id:event.pointerId,node,p,clientX:event.clientX,clientY:event.clientY,x:node?.x,y:node?.y,view:{...view}};wasDragged=false;root.setPointerCapture(event.pointerId);
  });
  root.addEventListener('pointermove',event=>{
    if(!drag||drag.id!==event.pointerId)return;
    const dist=Math.hypot(event.clientX-drag.clientX,event.clientY-drag.clientY);if(dist<3&&!wasDragged)return;wasDragged=true;
    if(drag.node){const p=point(event);drag.node.x=drag.x+p.x-drag.p.x;drag.node.y=drag.y+p.y-drag.p.y;drag.node.fixed=true;draw();}
    else{const rect=root.getBoundingClientRect(),scale=Math.max(drag.view.width/rect.width,drag.view.height/rect.height);view.x=drag.view.x-(event.clientX-drag.clientX)*scale;view.y=drag.view.y-(event.clientY-drag.clientY)*scale;camera();}
  });
  const end=event=>{if(drag?.id===event.pointerId){drag=null;if(root.hasPointerCapture(event.pointerId))root.releasePointerCapture(event.pointerId);}};
  root.addEventListener('pointerup',end);root.addEventListener('pointercancel',end);
  root.addEventListener('wheel',event=>{if(event.ctrlKey||event.metaKey){event.preventDefault();zoom(event.deltaY>0?1.1:.9);}},{passive:false});
  const header=el('div',{class:'panel-head'},el('div',{},el('h2',{},graph.title),el('p',{},graph.kind==='account'?`${graph.totalEntries} contributing entries · ${graph.unit} · ${graph.period}`:`Captured current APIs · ${graph.observed}`)),
    graph.kind==='entry'?button('Return to account context',()=>{S.entryFocus=null;loadView();},'button compact','arrow'):tag('Source-bound relationships','','branch'));
  content(header,el('section',{class:'graph-workspace'},canvas,inspector),note(`${graph.omittedEntries?graph.omittedEntries+' additional entries/objects are outside this bounded graph. ':''}Position and distance have no accounting meaning. Only returned references create links; this is not a proof of document authenticity or inferred money movement.`));
  const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;
  if(reduced)layout.step(190);
  draw();fit();highlights();renderObject(inspector,layout.nodes.find(n=>n.root)||layout.nodes[0],graph);
  function animate(){if(disposed||!stage.isConnected)return;if(!document.hidden&&!drag&&layout.active){layout.step(3);draw();}if(layout.active)frame=requestAnimationFrame(animate);else root.dataset.settled='true';}
  if(!reduced)frame=requestAnimationFrame(animate);else root.dataset.settled='true';
  graphCleanup=()=>{disposed=true;cancelAnimationFrame(frame);};
}
function renderObject(host,node,graph){
  const observed=graph.kind==='account'?'Pinned #'+graph.knownAt:graph.observed;
  const base=[['Reference',node.id],['Observation',observed]];
  if(node.commit)base.push(['Content commitment',node.commit]);
  if(node.detail?.amount)base.push(['Source leg amount',node.detail.amount],['Side',node.detail.side]);
  if(node.detail?.column)base.push(['Column',node.detail.column]);
  if(node.detail?.grade)base.push(['Grade',node.detail.grade]);
  if(node.detail?.recorded_at)base.push(['Recorded at','#'+node.detail.recorded_at]);
  set(host,el('p',{class:'eyebrow'},'CONNECTED OBJECT'),el('div',{class:'object-symbol'},icon(node.kind==='document'?'document':node.kind==='principal'?'person':node.kind==='account'?'wallet':'ledger')),
    el('h2',{},node.label),el('p',{},node.sub),el('div',{class:'detail-tags'},tag(node.kind),tag(node.root?'Focus object':'Referenced object')),
    metadata(base),el('div',{class:'detail-actions'},node.handle?button('Inspect current entry',()=>openEntry(node.handle),'button primary','arrow'):null,
      button('Copy reference',()=>copy(node.id),'button','copy')),
    el('p',{class:'scope-note'},node.kind==='document'?'This is a document reference, not its contents. A commitment alone does not establish that the underlying document is truthful.':'Select another object to highlight its immediate neighbors. Dragging pins only the visual position.'));
}

function metadata(pairs){return el('dl',{class:'metadata-list'},...pairs.filter(pair=>pair[1]!==undefined&&pair[1]!==null).map(([key,value])=>el('div',{},el('dt',{},key),el('dd',{class:typeof value==='string'&&value.length>=32?'hash':''},String(value)))));}
function fillInspector(title,node){$('#inspector-title').textContent=title;set('#inspector-content',node);$('#inspector').scrollTop=0;}
function inspect(title,node){detailGate.invalidate();fillInspector(title,node);if(!$('#inspector').open)$('#inspector').showModal();}
async function openAccount(account,period,known){
  const unit=S.unit;inspect(account+' · period detail',loading('Reading the contributing entries'));const current=detailGate.ticket();
  try{
    const result=await api('account',{account,period,known_at:known},current);if(!result)return;checkBook(result.report);snapshot(result.report,known);
    const b=body(result.report),cells=b.cells.filter(c=>c.unit===unit),contributions=b.contributions.filter(c=>parseAmount(c.amount).unit===unit);
    fillInspector(b.name,el('div',{},el('div',{class:'detail-tags'},tag(account),tag(period),tag('#'+known),tag(unit),S.meta.mode==='demo'?tag('Synthetic sample','warning'):null),
      el('div',{class:'detail-grid'},...cells.flatMap(c=>[['Period debits',c.debits],['Period credits',c.credits]].map(([label,value])=>el('div',{},el('small',{},label),el('strong',{},moneyText(value)))))),
      el('div',{class:'detail-actions'},button('Open evidence graph',()=>{S.account=account;S.period=period;S.known=known;S.entryFocus=null;navigate('graph');},'button primary','graph'),
        button('Copy fold digest',()=>copy(b.fold_digest),'button','copy')),
      panel('The contributing legs',contributions.length+' legs in the selected period',pages(contributions,c=>el('tr',{},el('td',{},button([c.class+' · '+c.effective_date,el('small',{},'#'+c.recorded_at+' · L'+c.ordinal)],()=>openEntry(c.entry),'entry-link')),
        el('td',{},tag(c.column,c.column==='pending'?'warning':'')),el('td',{},c.side),el('td',{class:'numeric'},amount(c.amount))),['Entry','Column','Side',{node:'Amount',numeric:true}],{label:'period legs'})),
      note('These are period movements, not cumulative stock. Opening history can make the overview balance different. Entry inspection below uses current APIs and labels their observations.'),
      metadata([['Fold digest',b.fold_digest],['Account vertex',b.account_vid],['Native snapshot','#'+known]])));
  }catch(error){if(current())fillInspector('Account read failed',errorPanel(error,()=>openAccount(account,period,known)));}
}
async function openEntry(vid){
  inspect('Entry & evidence',loading('Resolving this entry and its source references'));const current=detailGate.ticket();
  try{
    const result=await api('entry',{vid},current);if(!result)return;checkBook(result.entry);checkBook(result.evidence);
    if(body(result.entry).vid!==vid||body(result.evidence).entry!==vid||body(result.entry).entry_digest!==body(result.evidence).entry_digest)throw new Error('Entry and evidence references disagree.');
    const b=body(result.entry),e=body(result.evidence),tabContent=el('div');
    const tabNames=['Overview','Evidence','Lineage'];
    const tabs=el('div',{class:'tab-bar'},...tabNames.map((name,i)=>button(name,()=>showTab(i),'')));
    function showTab(index){[...tabs.children].forEach((n,i)=>n.setAttribute('aria-pressed',i===index));
      if(index===0)set(tabContent,b.description?el('div',{class:'untrusted'},el('small',{},'ENTRY-AUTHORED TEXT · '+b.description.source),b.description.untrusted_content):el('p',{},'No description was disclosed.'),
        metadata([['Recorded at','#'+b.recorded_at],['Effective date',b.effective_date],['Principal',b.principal],['Approvals',b.approvals],['Entry digest',b.entry_digest]]),
        panel('Resolved legs','Exact native units · leg presence alone does not establish posted status',pages(b.legs,leg=>el('tr',{},el('td',{},el('div',{class:'account-name'},leg.account,el('small',{},leg.account_name))),el('td',{},leg.side),el('td',{class:'numeric'},moneyText(leg.amount,true))),['Account','Side',{node:'Amount',numeric:true}],{label:'legs'})));
      else if(index===1)set(tabContent,el('div',{class:'detail-tags'},tag(e.satisfied?'Native evidence minimum met':'Native evidence minimum not met',e.satisfied?'good':'bad'),tag('Minimum: '+e.min_documents+' document(s)')),
        ...e.documents.map(doc=>el('article',{class:'document-card'},el('h3',{},doc.kind,tag(doc.grade,doc.self_sourced?'warning':'')),
          el('div',{class:'detail-tags'},tag(doc.role_name||'Role '+doc.role),tag(doc.counts_toward_minimum?'Counts toward minimum':'Does not count',doc.counts_toward_minimum?'good':'warning')),
          metadata([['Document OID',doc.document_oid],['Content commitment',doc.doc_commit],['Size',doc.size+' bytes'],['Recorded at','#'+doc.recorded_at]]),
          ...doc.reviews.map(review=>el('p',{class:'hash'},'Review '+review.attestation_vid+' · reviewer '+review.reviewer+' · #'+review.recorded_at)),
          el('p',{},doc.reviews.length+' review(s) · '+doc.supplements.length+' supplement(s)'))),
        ...e.manual_assertions.map(assertion=>el('p',{},'Manual assertion '+assertion.attestation_vid+' · '+(assertion.reason||assertion.reason_code))),
        note('A satisfied evidence minimum is not proof of document authenticity or economic truth. No document bytes are downloaded.'));
      else{const links=[...b.supersedes.map(l=>({...l,direction:'Supersedes'})),...b.superseded_by.map(l=>({...l,direction:'Superseded by'}))];
        set(tabContent,links.length?el('div',{},...links.map(link=>el('div',{class:'document-card'},el('h3',{},link.direction+' · '+link.kind),el('p',{},link.reason||'Reason '+link.reason_code),
          button(short(link.entry,24),()=>openEntry(link.entry),'text-link','arrow')))):empty('No supersession links returned.','This is the observed current lineage, not a claim about all future history.',null,'branch'),
          b.resolves?metadata([['Resolves entry',b.resolves],['Disposition',b.disposition]]):null);}
    }
    fillInspector(b.class+' entry',el('div',{},el('div',{class:'detail-tags'},tag(b.period||'Book scope'),tag('Recorded #'+b.recorded_at),S.meta.mode==='demo'?tag('Synthetic sample','warning'):null),
      el('p',{class:'scope-note'},`Entry observed #${at(result.entry)} · evidence observed #${at(result.evidence)}. These current API reads are separate from your historical report.`),
      el('div',{class:'detail-actions'},button('Explore entry graph',()=>{S.entryFocus=result;navigate('graph');},'button primary','graph'),button('Copy entry handle',()=>copy('E:'+b.vid),'button','copy')),
      tabs,el('div',{class:'flow-rule'}),tabContent));showTab(0);
  }catch(error){if(current())fillInspector('Entry inspection failed',errorPanel(error,()=>openEntry(vid)));}
}
function renderPeriods(){
  const periods=body(S.meta.periods).periods;
  const cards=periods.map(p=>el('article',{class:'panel period-card'},el('div',{class:'period-top'},el('h2',{},p.code),tag(p.state,p.state.toLowerCase()==='open'?'good':p.state.toLowerCase().includes('soft')?'warning':'')),
    el('div',{class:'period-days'},el('div',{},el('small',{},'Start'),p.start),el('div',{},el('small',{},'End boundary'),p.end)),
    el('div',{class:'detail-tags'},tag(p.kind),tag('FY '+p.fiscal_year)),button('View this period',()=>{S.period=p.code;S.entryFocus=null;navigate('overview');},'button','arrow')));
  content(periods.length?el('section',{class:'period-grid'},...cards):empty('No fiscal periods returned.','Create periods using the native CLI, then refresh.'),
    note('These are current calendar-state observations at #'+at(S.meta.periods)+'. The raw end boundary is displayed as returned; historical reports have their own explicit effective cutoff. There are no close or reopen controls.'));
}
function renderHealth(result){
  const b=body(result.report);
  const checks=el('div',{},...b.derived.map(c=>el('article',{class:'check-row'},el('h3',{},c.name,tag(c.status,c.status==='ok'?'good':c.status==='fail'?'bad':'warning')),
    el('p',{},c.detail),c.fix?el('code',{},c.fix):null)));
  const projection=el('div');
  async function run(){set(projection,loading('Running the native projection comparison'));
    const current=()=>S.view==='health'&&projection.isConnected;
    try{const answer=await api('projections',{},current);if(!answer)return;
      const r=answer.report,d=r.data;
      if(!r.failed&&(!d||!Array.isArray(d.drift)))throw new Error('Native projection check omitted its verdict detail.');
      const red=r.failed||(d?.drift?.length||0)>0;
      set(projection,panel(red?'Native projection result is red':'Leg projections agree with the native payloads',d?'Observed at #'+d.known_at:'Native failure details',el('div',{class:'panel-body'},
        tag(S.meta.mode==='demo'?'Synthetic result — native check not run':red?'Projection discrepancy':'Projection comparison passed',S.meta.mode==='demo'?'warning':red?'bad':'good'),
        d?el('p',{},`${d.entries_checked} entries · ${d.legs_checked} legs · ${d.edges_checked} expected edges`):null,
        ...(d?.drift||[]).map(item=>el('p',{},item)),r.error?el('pre',{class:'native-json'},JSON.stringify(r.error,null,2)):null,
        note('This compares derived leg mirrors and topology. It does not certify source immutability, evidence truth, or an offline proof.'))));
    }catch(error){if(current())set(projection,errorPanel(error,run));}
  }
  content(el('section',{class:'metrics'},metric('Native triage',b.health,'Declared diagnostic result','OBSERVED #'+at(result.report),'shield',b.health==='ok'?'featured':''),
    metric('Daemon',b.daemon,'Native routing observation','LOCAL','branch'),metric('Due holds',b.due_holds,'Committed time-evidence basis','NATIVE TRIAGE','time'),
    metric('Blocked reversals',b.blocked_reversals,'Native period-law blockers','NATIVE TRIAGE','warning','coral')),
    panel('Derived-state observations','Every status retains its native detail and scope.',checks),el('div',{class:'detail-actions'},button('Run projection check',run,'button primary','shield')),
    projection,note('Checks are explicit, not background polling. No journal object is created and no automatic repair is attempted. A positive result only covers the predicate named by that check.'));
}
function viewScope(){
  inspect('Exactly what you are seeing',el('div',{},el('div',{class:'detail-tags'},tag(S.meta?.mode==='demo'?'Synthetic preview':'Local owner read',S.meta?.mode==='demo'?'warning':''),tag('Read-only')),
    S.scope?metadata(Object.entries(S.scope)):el('p',{},'No result is active. Apply a selection before citing or exporting a scope.'),
    note('Amounts remain exact native-unit values. A display, CSV, graph, or row difference is not a signed report certificate or independent proof.'),
    S.scope?button('Copy this scope',()=>copy(JSON.stringify({mode:S.meta.mode,...S.scope},null,2)),'button primary','copy'):null));
}
function sessionInfo(){inspect('Your local workspace',el('div',{},metadata([['Data mode',S.meta?.mode||'Not connected'],['Display label',S.meta?.title||'Not loaded'],['Book ID',S.meta?.book?.book],
  ['Connection',location.origin],['Authority','Owner CLI principal claim; not human authentication'],['Writes','No posting, closing, settlement, or repair endpoint']]),
  el('p',{},'The native engine owns the ledger and its authority checks. This browser is a read-only presentation companion. Keep the private launch URL and downloaded data protected.'),
  note('No cloud account, external fonts, analytics, or telemetry. Do not expose the loopback service through a tunnel or reverse proxy.')));}
function help(){inspect('Built around the evidence',el('div',{},el('h3',{},'Two times, two different questions.'),el('p',{},'Effective time says which accounting period a report describes. Recorded time says what the journal knew at a particular commit. Time lens keeps the first fixed while comparing the second.'),
  el('h3',{},'Move from amount to evidence.'),el('p',{},'Open an account’s period detail, choose a contributing entry, then explore its documents and supersession links. The graph draws only references returned by the native API.'),
  el('h3',{},'Stay oriented.'),el('p',{},'View scope identifies the active result. Changing a selector clears the old result. Refresh to latest deliberately reads a new snapshot; nothing silently polls a moving book.'),
  el('h3',{},'Keyboard-first.'),el('p',{},'Cmd/Ctrl-K opens workspace search. Use arrow keys and Enter to choose a result. Tab through chart points and graph nodes; Enter inspects. Escape closes the inspector.'),
  note('Ages mean days since the effective date, not overdue invoices. Relationship positions do not represent amounts or inferred flow. Figures in the sample workspace are synthetic.'),
  el('div',{class:'detail-actions'},el('a',{href:'/reports.html#ledger',class:'button'},'Classic report page ↗'))));}
function openCommands(){
  $('#command-input').value='';searchCommands('');if(!$('#command-dialog').open)$('#command-dialog').showModal();$('#command-input').focus();
}
function searchCommands(term){
  const items=Object.keys(names).map(view=>({label:names[view][0],detail:'View',symbol:view==='compare'?'time':view==='health'?'shield':view==='periods'?'calendar':view==='accounts'?'wallet':view,run:()=>navigate(view)}));
  const seen=new Set();for(const row of S.overview?body(S.overview.stock).rows:[]){if(seen.has(row.code))continue;seen.add(row.code);items.push({label:row.code+' · '+row.name,detail:'Account',symbol:'wallet',run:()=>openAccount(row.code,S.period,at(S.overview.stock))});}
  commandOptions=items.filter(item=>item.label.toLowerCase().includes(term.toLowerCase())).slice(0,12);
  const vid=term.trim().replace(/^E:/,'');if(/^[0-9a-fA-F]{32}$/.test(vid))commandOptions.unshift({label:'Inspect entry '+short(vid,16),detail:'Current read',symbol:'document',run:()=>openEntry(vid.toLowerCase())});
  commandIndex=0;drawCommands();
}
function drawCommands(){
  set('#command-results',...commandOptions.map((item,i)=>el('div',{class:'command-option',id:'command-result-'+i,role:'option','aria-selected':i===commandIndex,
    onpointerenter:()=>{commandIndex=i;highlightCommands();},onclick:()=>chooseCommand(i)},icon(item.symbol),el('span',{},item.label),el('small',{},item.detail))));
  if(!commandOptions.length)set('#command-results',el('p',{class:'scope-note'},'No matching view or account. Paste a complete 32-hex entry handle to inspect it.'));
  highlightCommands();
}
function highlightCommands(){document.querySelectorAll('.command-option').forEach((n,i)=>n.setAttribute('aria-selected',i===commandIndex));if(commandOptions.length)$('#command-input').setAttribute('aria-activedescendant','command-result-'+commandIndex);else $('#command-input').removeAttribute('aria-activedescendant');}
function chooseCommand(index){const item=commandOptions[index];if(item){$('#command-dialog').close();item.run();}}
function theme(value){document.documentElement.dataset.theme=value;set('#theme-button',icon(value==='dark'?'sun':'moon'));$('#theme-button').setAttribute('aria-label','Switch to '+(value==='dark'?'light':'dark')+' theme');try{localStorage.setItem('fa-dashboard-theme',value);}catch{}}
for(const node of document.querySelectorAll('[data-icon]'))node.replaceChildren(icon(node.dataset.icon));
set('#search-icon',icon('search'));
try{theme(localStorage.getItem('fa-dashboard-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'));}catch{theme('light');}
$('#theme-button').addEventListener('click',()=>theme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
$('#scope-form').addEventListener('submit',event=>{event.preventDefault();S.entryFocus=null;loadView();});
$('#refresh-button').addEventListener('click',()=>{S.known='HEAD';S.entryFocus=null;boot();});
$('#scope-button').addEventListener('click',viewScope);$('#help-button').addEventListener('click',help);
$('#session-button').addEventListener('click',sessionInfo);$('#profile-button').addEventListener('click',sessionInfo);
$('#rail-explore').addEventListener('click',()=>navigate('compare'));
$('.brand').addEventListener('click',event=>{event.preventDefault();navigate('overview');});
document.querySelectorAll('[data-view]').forEach(node=>node.addEventListener('click',event=>{event.preventDefault();navigate(node.dataset.view);}));
$('#inspector-close').addEventListener('click',()=>$('#inspector').close());$('#inspector').addEventListener('close',()=>detailGate.invalidate());
$('#command-button').addEventListener('click',openCommands);$('#mobile-command-button').addEventListener('click',openCommands);$('#command-close').addEventListener('click',()=>$('#command-dialog').close());
$('#command-input').addEventListener('input',event=>searchCommands(event.target.value));
$('#command-input').addEventListener('keydown',event=>{
  if(['ArrowDown','ArrowUp','Enter'].includes(event.key))event.preventDefault();
  if(!commandOptions.length)return;
  if(event.key==='ArrowDown')commandIndex=(commandIndex+1)%commandOptions.length;
  if(event.key==='ArrowUp')commandIndex=(commandIndex-1+commandOptions.length)%commandOptions.length;
  if(event.key==='Enter')chooseCommand(commandIndex);else{highlightCommands();document.getElementById('command-result-'+commandIndex)?.scrollIntoView({block:'nearest'});}
});
document.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='k'){event.preventDefault();if(!$('#inspector').open&&!$('#command-dialog').open)openCommands();}});
window.addEventListener('hashchange',()=>{const name=location.hash.slice(1);if(names[name]&&name!==S.view)navigate(name);});
window.addEventListener('pagehide',()=>{mainGate.invalidate();detailGate.invalidate();spotlightGate.invalidate();graphCleanup();});
updateHeader();boot();
