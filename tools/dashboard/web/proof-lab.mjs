const $=s=>document.querySelector(s);
let token=new URLSearchParams(location.hash.slice(1)).get('token');
try{if(token){sessionStorage.setItem('fa-dashboard-token',token);history.replaceState(null,'',location.pathname)}else token=sessionStorage.getItem('fa-dashboard-token')}catch{if(token)history.replaceState(null,'',location.pathname)}
const state={mode:'live',book:null,chain:null,proof:null};
function api(path){return fetch(path,{headers:{Authorization:'Bearer '+(token||'')},cache:'no-store',credentials:'omit'}).then(async r=>{const b=await r.json();if(!r.ok){const e=new Error(b.error||'Native read failed.');e.detail=b.detail;throw e}return b})}
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text);return n}
function clear(n){n.replaceChildren()}
function showError(error){const box=$('#message');box.hidden=false;box.textContent=error.detail?.message?error.message+' '+error.detail.message:error.message}
function hideError(){$('#message').hidden=true;$('#message').textContent=''}
function theme(v){document.documentElement.dataset.theme=v;try{localStorage.setItem('fa-dashboard-theme',v)}catch{}}
try{theme(localStorage.getItem('fa-dashboard-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'))}catch{theme('light')}
$('#theme').addEventListener('click',()=>theme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
function stat(label,value){const d=el('div','lab-stat');d.append(el('span','',label),el('strong','',value));return d}
function renderChain(report){
  const root=$('#chain');clear(root);const d=report.data||{},failed=report.failed===true;
  const summary=el('div','lab-chain-summary');
  summary.append(stat('STATUS',failed?'verification failure':d.status||'unknown'),stat('STATES',d.states_checked??0),stat('VERIFIED THROUGH',d.verified_through===null?'—':'#'+d.verified_through),stat('SIGNATURES',d.signatures||'unknown'));
  root.append(summary);
  if(failed){const box=el('div','lab-state lab-red');box.append(el('strong','','Native verification is red'),el('small','',report.error?.message||'The native accumulator checker reported a mismatch.'));root.append(box);return}
  const states=Array.isArray(d.states)?d.states:[];
  const select=$('#state');clear(select);select.append(new Option('Latest recorded state','latest'));
  const track=el('div','lab-track');
  for(const item of states){
    const row=el('div','lab-state'+(item.finding?' lab-red':'')),left=el('div'),right=el('div');
    left.append(el('code','',item.oid),el('small','',`Covers ${item.leaf_count} entries through #${item.through_seq} · recorded #${item.recorded_at}${item.finding?' · '+item.finding:''}`));
    const choose=el('button','', 'Use this checkpoint →');choose.type='button';choose.addEventListener('click',()=>{$('#state').value=item.oid;$('#state').focus()});right.append(choose);row.append(left,right);track.append(row);
    select.append(new Option(`#${item.through_seq} · ${item.oid.slice(0,12)}…`,item.oid));
  }
  if(!states.length)track.append(el('div','lab-state', 'No recorded checkpoints. Create one with the native CLI before exporting proofs.'));
  root.append(track);
}
async function refresh(){
  hideError();const root=$('#chain');root.innerHTML='<div class="lab-loading">Reading and recomputing recorded checkpoint states…</div>';
  try{const r=await api('/api/checkpoints');state.chain=r.report;renderChain(r.report)}catch(e){root.innerHTML='<div class="lab-state lab-red">Checkpoint-chain read failed. No synthetic success was substituted.</div>';showError(e)}
}
function fields(){
  const k=$('#kind').value;
  $('#entry-field').hidden=k!=='inclusion';$('#record-field').hidden=k!=='inclusion';
  $('#account-field').hidden=k!=='balance';$('#unit-field').hidden=k!=='balance';$('#date-field').hidden=k!=='balance';
}
$('#kind').addEventListener('change',fields);fields();
function verifyCommand(body){
  const key=body.checkpoint_public_key,kind=body.kind;
  if(kind==='signed-checkpoint')return `fa-verify checkpoint <signed-checkpoint-file> --key ${key} --json`;
  if(kind==='checkpoint')return 'Trust the raw 80-byte checkpoint statement externally before using --unsigned-checkpoint.';
  const cmd=[`fa-verify ${kind}`,'--proof <proof-file>','--checkpoint <signed-checkpoint-file>',`--key ${key}`,'--json'];
  return cmd.join(' ');
}
function downloadHex(hex,name){
  const bytes=new Uint8Array(hex.length/2);for(let i=0;i<bytes.length;i++)bytes[i]=parseInt(hex.slice(i*2,i*2+2),16);
  const url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)
}
function renderProof(event){
  const root=$('#proof-result');clear(root);root.hidden=false;root.className='proof-card lab-proof';const d=event.data;
  const head=el('div','lab-section-head'),left=el('div');left.append(el('div','eyebrow','PORTABLE PROOF EXPORTED'),el('h3','',d.kind),el('p','',`Recorded state ${d.state_oid.slice(0,12)}… · ${d.byte_len} bytes · ${d.signatures}`));head.append(left,el('span','proof-chip',d.trust));root.append(head);
  const grid=el('div','lab-proof-grid'),meta=el('div','lab-proof-meta');
  [['Scope',d.scope],['Through','#'+d.through_seq],['Leaf count',d.leaf_count],['Root',d.root],['State',d.state_oid],['Checkpoint key',d.checkpoint_public_key]].forEach(([k,v])=>{const cell=el('div');cell.append(el('span','',k.toUpperCase()),el('strong','',v));meta.append(cell)});
  const side=el('div');side.append(el('div','lab-command',verifyCommand(d)));const acts=el('div','lab-actions');
  const dl=el('button','', 'Download proof bytes');dl.type='button';dl.addEventListener('click',()=>downloadHex(d.bytes,`fa-${d.kind}-${d.state_oid.slice(0,12)}.bin`));
  const copy=el('button','', 'Copy verify command');copy.type='button';copy.addEventListener('click',()=>navigator.clipboard?.writeText(verifyCommand(d)));
  acts.append(dl,copy);side.append(acts);grid.append(meta,side);root.append(grid);
  root.append(el('div','lab-bytes',d.bytes.length>4096?d.bytes.slice(0,4096)+'…':d.bytes),el('p','proof-report-note',d.bytes.length>4096?'Preview truncated visually; downloaded bytes are complete.':'Complete inline proof bytes shown above.'));
}
async function exportProof(e){
  e.preventDefault();hideError();const params=new URLSearchParams({kind:$('#kind').value,state:$('#state').value||'latest'});
  if($('#kind').value==='inclusion'){params.set('entry',$('#entry').value.trim());params.set('with_record',$('#with-record').checked?'1':'0')}
  if($('#kind').value==='balance'){params.set('account',$('#account').value.trim());params.set('unit',$('#unit').value.trim());if($('#as-of').value)params.set('as_of',$('#as-of').value)}
  const root=$('#proof-result');root.hidden=false;root.className='proof-card lab-proof';root.innerHTML='<div class="lab-loading">Exporting native proof bytes from the selected recorded state…</div>';
  try{const r=await api('/api/proof-export?'+params);state.proof=r.proof;renderProof(r.proof)}catch(err){root.hidden=true;showError(err)}
}
$('#proof-form').addEventListener('submit',exportProof);$('#refresh-chain').addEventListener('click',refresh);
api('/api/bootstrap').then(meta=>{state.mode=meta.mode;state.book=meta.book?.data?.book_id;$('#book-title').textContent=meta.title;$('#mode-chip').textContent=meta.mode==='demo'?'SYNTHETIC':'LOCAL';$('#demo-warning').hidden=meta.mode!=='demo';if(meta.mode==='demo'){$('#entry').value='1'.repeat(32);$('#account').value='1000';$('#unit').value='USD'}}).catch(()=>{});
refresh();
