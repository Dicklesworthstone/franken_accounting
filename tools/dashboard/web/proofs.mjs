const $=s=>document.querySelector(s);
let token=new URLSearchParams(location.hash.slice(1)).get('token');
try{if(token){sessionStorage.setItem('fa-dashboard-token',token);history.replaceState(null,'',location.pathname)}else token=sessionStorage.getItem('fa-dashboard-token')}catch{if(token)history.replaceState(null,'',location.pathname)}
const state={mode:'live',oid:null,status:null,replay:null};
const esc=v=>String(v??'');
function api(path){return fetch(path,{headers:{Authorization:'Bearer '+(token||'')},cache:'no-store',credentials:'omit'}).then(async r=>{const b=await r.json();if(!r.ok){const e=new Error(b.error||'Native read failed.');e.detail=b.detail;throw e}return b})}
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n}
function clear(n){n.replaceChildren()}
function showError(error){const box=$('#message');box.hidden=false;box.textContent=error.detail?.message?error.message+' '+error.detail.message:error.message}
function hideError(){$('#message').hidden=true;$('#message').textContent=''}
function theme(v){document.documentElement.dataset.theme=v;try{localStorage.setItem('fa-dashboard-theme',v)}catch{}}
try{theme(localStorage.getItem('fa-dashboard-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'))}catch{theme('light')}
$('#theme').addEventListener('click',()=>theme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
function button(text,fn,secondary=false){const b=el('button','proof-action'+(secondary?' secondary':''),text);b.type='button';b.addEventListener('click',fn);return b}
function amount(v){const span=el('span','',v);span.style.fontVariantNumeric='tabular-nums';return span}
function table(headers,rows){const wrap=el('div','table-wrap');const t=el('table','proof-table');const thead=el('thead');const tr=el('tr');headers.forEach(h=>tr.append(el('th','',h)));thead.append(tr);const body=el('tbody');rows.forEach(row=>{const tr=el('tr');row.forEach((cell,i)=>{const td=el('td',i? 'num':'');if(cell instanceof Node)td.append(cell);else td.textContent=esc(cell);tr.append(td)});body.append(tr)});t.append(thead,body);wrap.append(t);return wrap}
function replayView(event){
  const d=event.data,kind=event.event,box=el('section','proof-card proof-replay');
  const head=el('div','proof-replay-head'),left=el('div');left.append(el('h3','',kind.replaceAll('_',' ')),el('p','',`Replayed at original coordinate #${event.coordinate?.known_at} · certificate ${state.oid?.slice(0,12)}…`));head.append(left);box.append(head);
  if(kind==='trial_balance'){
    box.append(table(['Account','Debits','Credits','Net'],(d.rows||[]).slice(0,30).map(r=>[r.code+' · '+r.name,r.debits,r.credits,r.net])));
    if((d.rows||[]).length>30)box.append(el('p','proof-report-note',`Showing 30 of ${d.rows.length} account/unit rows.`));
  }else if(kind==='statement'){
    box.append(table(['Line','Unit','Amounts'],(d.lines||[]).slice(0,30).map(r=>[r.code+' · '+r.label,r.unit,(r.amounts||[]).join(' · ')])));
  }else if(kind==='balance_explained'){
    box.append(table(['Unit','Debits','Credits','Net'],(d.cells||[]).map(r=>[r.unit,r.debits,r.credits,r.net])));
    box.append(el('p','proof-report-note',`${(d.contributions||[]).length} contributing legs retained in the replayed explanation.`));
  }else if(kind==='open_items'){
    box.append(table(['Entry','Side','Open','Effective'],(d.items||[]).slice(0,30).map(r=>[r.entry,r.side,r.open,r.effective_date])));
  }else box.append(el('p','proof-report-note','The native replay returned a supported report, but this browser version has no specialized renderer.'));
  box.append(el('p','proof-report-note','Replay preserves the retained report selector and known-at coordinate. This presentation is not a separate certificate or trust anchor.'));
  return box
}
function inspectEntry(vid){
  const dialog=$('#entry-dialog'),content=$('#entry-content');clear(content);content.append(el('h2','', 'Later entry'),el('code','',vid),el('p','muted','Reading current entry/evidence observation…'));dialog.showModal();
  api('/api/entry?vid='+encodeURIComponent(vid)).then(result=>{
    clear(content);const e=result.entry.data,v=result.evidence.data;
    content.append(el('div','eyebrow',`CURRENT ENTRY OBSERVATION · #${result.entry.coordinate.known_at}`),el('h2','',e.class+' · '+e.effective_date),el('code','',e.vid));
    if(e.description?.untrusted_content)content.append(el('p','muted',e.description.untrusted_content));
    (e.legs||[]).forEach(l=>{const row=el('div','leg');row.append(el('span','',`${l.side} · ${l.account} · ${l.account_name}`),amount(l.amount));content.append(row)});
    content.append(el('p','muted',`Evidence observed at #${result.evidence.coordinate.known_at}: ${(v.documents||[]).length} cited document(s). Current evidence is not backdated into the certificate's historical snapshot.`));
  }).catch(e=>{clear(content);content.append(el('h2','', 'Entry read failed'),el('p','muted',e.message))})
}
function renderStatus(){
  const root=$('#result');clear(root);const s=state.status.data;
  const grid=el('div','proof-status-grid'),card=el('section','proof-card'),scope=el('section','proof-card');
  const verdict=el('div','proof-verdict');verdict.append(el('strong',s.status==='Current'?'current':'superseded',s.status),el('span','proof-chip',`${s.later_entries.length} later entr${s.later_entries.length===1?'y':'ies'}`));card.append(verdict);
  const line=el('div','proof-timeline'),a=el('div','proof-time'),b=el('div','proof-time');a.append(el('small','', 'ORIGINAL KNOWN AT'),el('strong','', '#'+s.known_at));b.append(el('small','', 'STATUS CHECKED AT'),el('strong','', '#'+s.checked_at));line.append(a,el('i'),b);card.append(line);
  card.append(el('p','',s.status==='Current'?'No later entry affects this retained report selector at the checked frontier.':'The original report remains replayable, but later entries now affect the same selector.'));
  const later=el('div','proof-later');(s.later_entries||[]).slice(0,12).forEach(vid=>{const row=el('div','proof-entry');row.append(el('code','',vid),button('Inspect current entry →',()=>inspectEntry(vid),true));later.append(row)});if(s.later_entries.length)card.append(later);
  const actions=el('div','proof-actions');actions.append(button('Replay original report',replay),button('Copy native replay command',()=>navigator.clipboard?.writeText(`fa replay C:${state.oid} --book <book-dir> --json`),true));card.append(actions);
  scope.append(el('h3','', 'Claim boundary'),el('p','', 'Status asks a current question. Replay asks a historical one. Neither makes this browser a verifier.'));
  const cells=el('div','proof-scope');
  [['Certificate',state.oid],['Replay scope',s.replay_scope],['Authority',s.authority],['Book',state.status.book],['Effective selector',state.status.coordinate?.effective],['Current check', '#'+s.checked_at]].forEach(([k,v])=>{const d=el('div');d.append(el('span','',k.toUpperCase()),el('strong','',v));cells.append(d)});scope.append(cells);
  grid.append(card,scope);root.append(grid);if(state.replay)root.append(replayView(state.replay))
}
async function inspect(){
  hideError();state.replay=null;const raw=$('#oid').value.trim();const oid=raw.replace(/^C:/,'').toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(oid)){showError(new Error('Enter C: followed by a 64-hex certificate id, or the 64-hex id itself.'));return}
  state.oid=oid;const root=$('#result');root.className='proof-empty';root.innerHTML='<div class="proof-orbit">◌</div><h2>Checking retained history…</h2><p>The native engine is evaluating the certificate against the current book.</p>';
  try{const result=await api('/api/certificate-status?oid='+oid);state.status=result.status;root.className='';renderStatus()}catch(e){root.className='proof-empty';root.innerHTML='<div class="proof-orbit">×</div><h2>No substituted result.</h2><p>The native certificate read failed or was refused.</p>';showError(e)}
}
async function replay(){
  hideError();if(!state.oid)return;const old=state.replay;state.replay=null;renderStatus();
  const root=$('#result');root.append(el('section','proof-card proof-replay', 'Replaying the retained native report…'));
  try{const result=await api('/api/certificate-replay?oid='+state.oid);state.replay=result.replay;renderStatus()}catch(e){state.replay=old;renderStatus();showError(e)}
}
$('#certificate-form').addEventListener('submit',e=>{e.preventDefault();inspect()});
$('#entry-close').addEventListener('click',()=>$('#entry-dialog').close());
api('/api/bootstrap').then(meta=>{state.mode=meta.mode;$('#book-title').textContent=meta.title;$('#mode-chip').textContent=meta.mode==='demo'?'SYNTHETIC':'LOCAL';$('#demo-warning').hidden=meta.mode!=='demo';if(meta.mode==='demo'){$('#oid').value='a'.repeat(64)}}).catch(()=>{});
