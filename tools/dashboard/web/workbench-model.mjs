// Exact, source-bound presentation models. Graph positions are never money.
import {parseAmount, zero, subtract, compare, format, csvCell} from './amounts.mjs';
import {requireThat as check, dayNumber} from './report-model.mjs';

export function sequence(value) {
  check(typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value), 'Use an exact commit sequence.');
  const n = BigInt(value); check(n < 2n ** 64n, 'Commit sequence exceeds u64.'); return n;
}
export function snapshot(event, expected) {
  check(event && typeof event.book === 'string' && /^[a-f0-9]{32}$/.test(event.book), 'Missing book identity.');
  check(event.coordinate?.branch === 'trunk', 'Only trunk reports are supported.');
  sequence(event.coordinate.known_at);
  if (expected && expected !== 'HEAD') check(event.coordinate.known_at === expected, 'Report snapshot differs from selection.');
  if (event.data?.known_at !== undefined) check(event.data.known_at === event.coordinate.known_at, 'Native snapshot fields disagree.');
  return event.coordinate.known_at;
}
const MONEY = ['debits', 'credits', 'debits_pending', 'credits_pending'];
export function stockRows(event) {
  snapshot(event);
  check(Array.isArray(event.data.rows), 'Missing native account rows.');
  const seen = new Set();
  return event.data.rows.map(row => {
    check(typeof row.code === 'string' && row.code.length > 0 && typeof row.name === 'string' && typeof row.type === 'string', 'Invalid account metadata.');
    const values = Object.fromEntries(MONEY.map(key => [key, parseAmount(row[key])]));
    const unit = values.debits.unit, key = JSON.stringify([row.code, unit]);
    check(!seen.has(key), 'Duplicate account/unit row.'); seen.add(key);
    for (const value of Object.values(values)) check(value.unit === unit && value.n >= 0n, 'Invalid or mixed-unit account columns.');
    check(parseAmount(row.net).unit === unit, 'Native net has a different unit.');
    return {...row, key, unit, values, balance: subtract(values.debits, values.credits)};
  });
}
export function comparisonModel(result, selection, unit) {
  check(result.scope === 'native-stock-snapshot-comparison', 'Unsupported comparison scope.');
  const a = result.before, b = result.after;
  const beforeAt = snapshot(a, selection.before), afterAt = snapshot(b, selection.after);
  check(sequence(beforeAt) <= sequence(afterAt), 'Comparison snapshots are reversed.');
  check(result.before_known_at === beforeAt && result.after_known_at === afterAt, 'Comparison envelope disagrees with native snapshots.');
  check(a.book === b.book && a.data.activity === false && b.data.activity === false, 'Comparison must use stock in one book.');
  check(a.data.periods.length === 1 && a.data.periods[0] === selection.period &&
        b.data.periods.length === 1 && b.data.periods[0] === selection.period &&
        a.data.effective_through === b.data.effective_through && a.data.mode === b.data.mode, 'Comparison effective scopes differ.');
  dayNumber(a.data.effective_through);
  check(typeof a.data.balanced === 'boolean' && typeof b.data.balanced === 'boolean', 'Missing native balance verdict.');
  const left = new Map(stockRows(a).map(row => [row.key, row]));
  const right = new Map(stockRows(b).map(row => [row.key, row]));
  const rows = [];
  for (const key of new Set([...left.keys(), ...right.keys()])) {
    const before = left.get(key) || null, after = right.get(key) || null, row = after || before;
    if (row.unit !== unit) continue;
    const origin = zero(unit, row.balance.scale);
    const delta = subtract(after?.balance || origin, before?.balance || origin);
    const deltaColumns = Object.fromEntries(MONEY.map(name => [name, subtract(after?.values[name] || origin, before?.values[name] || origin)]));
    const moneyChanged = Object.values(deltaColumns).some(value => value.n !== 0n);
    const metadataChanged = !!(before && after && (before.name !== after.name || before.type !== after.type));
    const status = !before ? 'added' : !after ? 'removed' : moneyChanged ? 'changed' : metadataChanged ? 'metadata' : 'unchanged';
    rows.push({key, code: row.code, name: row.name, type: row.type, unit, before, after, delta, deltaColumns, moneyChanged, metadataChanged, status});
  }
  rows.sort((x, y) => x.code.localeCompare(y.code, 'en', {numeric: true}));
  return {rows, beforeAt, afterAt, book: a.book, period: selection.period, effectiveThrough: a.data.effective_through,
    changed: rows.filter(row => row.status !== 'unchanged').length,
    balancedBefore: a.data.balanced, balancedAfter: b.data.balanced};
}
export function comparisonCsv(model, mode, rows = model.rows) {
  const headers = ['mode','book','period','effective_through','before_known_at','after_known_at','account','unit','status','before_present','after_present','before_debit_minus_credit','after_debit_minus_credit','delta_debit_minus_credit'];
  const values = rows.map(row => [mode, model.book, model.period, model.effectiveThrough, model.beforeAt, model.afterAt,
    row.code, row.unit, row.status, row.before !== null, row.after !== null,
    row.before ? format(row.before.balance, true) : '', row.after ? format(row.after.balance, true) : '', format(row.delta, true)]);
  return '\ufeff' + [headers,...values].map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
function id(value, size) { check(typeof value === 'string' && new RegExp(`^[a-f0-9]{${size}}$`).test(value), 'Malformed graph reference.'); return value; }
function builder(root) {
  const nodes = new Map(), edges = [], edgeIds = new Set();
  return {nodes, edges,
    node(n) {
      const previous = nodes.get(n.id);
      if (previous?.detail?.entry_digest && n.detail?.entry_digest) check(previous.detail.entry_digest === n.detail.entry_digest, 'One entry identity has conflicting payload digests.');
      if (previous?.commit && n.commit) check(previous.commit === n.commit, 'One document identity has conflicting commitments.');
      if (!previous) nodes.set(n.id, {...n, root: n.id === root});
      return n.id;
    },
    edge(source, target, relation, detail = null, qualifier = '') {
      const key = JSON.stringify([source, target, relation, qualifier]);
      if (!edgeIds.has(key)) {edges.push({id:key,source,target,relation,detail});edgeIds.add(key);}
    },
    finish(meta) {
      check(nodes.size <= 220 && edges.length <= 600, 'Graph exceeds the interactive view bound; narrow the selection.');
      for (const edge of edges) check(nodes.has(edge.source) && nodes.has(edge.target), 'Graph edge has no known endpoint.');
      return {...meta, root, nodes:[...nodes.values()], edges};
    }
  };
}
export function accountGraph(event, unit, maxEntries = 32) {
  const knownAt = snapshot(event), body = event.data;
  check(Number.isInteger(maxEntries) && maxEntries >= 1 && maxEntries <= 48, 'Invalid graph bound.');
  check(Array.isArray(body.contributions), 'Missing contribution list.');
  const root = 'account:' + id(body.account_vid, 32), graph = builder(root);
  graph.node({id:root,kind:'account',label:body.name,sub:body.account,detail:body});
  const all = body.contributions.filter(c => parseAmount(c.amount).unit === unit);
  const allEntries = new Set(all.map(c => id(c.entry,32)));
  const included = new Set([...allEntries].slice(0,maxEntries));
  for (const c of all) {
    if (!included.has(c.entry)) continue;
    check(sequence(c.recorded_at) <= sequence(knownAt), 'Contribution lies beyond graph snapshot.');
    check(['posted','pending','released'].includes(c.column), 'Unknown contribution column.');
    const e = graph.node({id:'entry:'+c.entry,kind:'entry',label:c.class,sub:'#'+c.recorded_at,handle:c.entry,detail:c});
    graph.edge(e,root,c.column,{amount:c.amount,side:c.side,ordinal:c.ordinal},String(c.ordinal));
    for (const citation of (c.evidence || [])) {
      const doc = graph.node({id:'document:'+id(citation.document_oid,64),kind:'document',label:'Source document',
        sub:citation.document_oid.slice(0,8)+'…',commit:id(citation.doc_commit,64),detail:citation});
      graph.edge(e,doc,'cites',citation,String(citation.role));
    }
  }
  return graph.finish({kind:'account',book:event.book,knownAt,period:body.period,unit,
    title:body.name,totalEntries:allEntries.size,omittedEntries:allEntries.size-included.size,
    totalContributions:all.length,observed:knownAt});
}
export function entryGraph(result) {
  const e = result.entry, evidence = result.evidence, knownAt = snapshot(e), evidenceAt = snapshot(evidence);
  const body = e.data, closure = evidence.data;
  check(e.book === evidence.book && body.vid === closure.entry && body.entry_digest === closure.entry_digest, 'Entry and evidence identities disagree.');
  const root = 'entry:'+id(body.vid,32), graph = builder(root);
  graph.node({id:root,kind:'entry',label:body.class,sub:'#'+body.recorded_at,handle:body.vid,detail:body});
  let omitted = 0;
  for (const [i, leg] of body.legs.entries()) {
    if (i >= 24) {omitted++;continue;}
    const account = graph.node({id:'account:'+id(leg.account_vid,32),kind:'account',label:leg.account_name,sub:leg.account,detail:leg});
    // A leg can be pending, released, or posted: its existence alone is not a posting claim.
    graph.edge(root,account,'leg account',leg,String(leg.ordinal));
  }
  for (const [i, doc] of closure.documents.entries()) {
    if (i >= 40) {omitted++;continue;}
    const target = graph.node({id:'document:'+id(doc.document_oid,64),kind:'document',label:doc.kind,sub:doc.grade,commit:id(doc.doc_commit,64),detail:doc});
    graph.edge(root,target,'cites',doc,String(doc.role));
  }
  const principal = graph.node({id:'principal:'+id(body.principal,32),kind:'principal',label:'Acting principal',sub:body.principal.slice(0,8)+'…',detail:{principal:body.principal}});
  graph.edge(principal,root,'prepared');
  const lineage = [...body.supersedes.map(l=>({...l,incoming:false})),...body.superseded_by.map(l=>({...l,incoming:true}))];
  for (const [i, link] of lineage.entries()) {
    if (i >= 16) {omitted++;continue;}
    const target = graph.node({id:'entry:'+id(link.entry,32),kind:'reference',label:link.kind,sub:link.entry.slice(0,8)+'…',handle:link.entry,detail:link});
    graph.edge(link.incoming?target:root,link.incoming?root:target,'supersession',link);
  }
  return graph.finish({kind:'entry',book:e.book,knownAt,evidenceAt,title:body.class,omittedEntries:omitted,
    totalEntries:1,observed:`entry #${knownAt} · evidence #${evidenceAt}`});
}
