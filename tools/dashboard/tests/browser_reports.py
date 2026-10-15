"""Offline DOM fixture check: deliberately no browser networking or native book."""
import argparse
import sys,json,re,base64
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--chromium', help='path to an already installed Chromium executable')
parser.add_argument('--screenshots', type=Path, help='optional output directory for synthetic preview screenshots')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
if args.screenshots:
    args.screenshots.mkdir(parents=True,exist_ok=True)

def screenshot(page,name):
    if args.screenshots:
        page.screenshot(path=str(args.screenshots/name),full_page=True)
from demo import DemoSource
from reports import dispatch
from serve import DashboardError,exact_transport
from playwright.sync_api import sync_playwright

source=DemoSource(DashboardError)

def fixture(path):
    url=urlsplit(path);params={k:v[0] for k,v in parse_qs(url.query).items()}
    try:
        if url.path=='/api/bootstrap': result=source.bootstrap()
        elif url.path=='/api/overview': result=source.overview(params['period'],params.get('known_at','HEAD'))
        elif url.path in ['/api/ledger','/api/aging']: result=dispatch(source,url.path,params,DashboardError)
        elif url.path=='/api/entry': result=source.entry(params['vid'])
        else: raise DashboardError('Unknown fixture route',404)
        return {'status':200,'body':exact_transport({'schema':'fa-dashboard/v1','read_only':True,'mode':'demo','title':'Northstar Studio · sample book',**result})}
    except DashboardError as e: return {'status':e.status,'body':{'error':str(e),'detail':e.detail}}

def uri(text):return 'data:text/javascript;base64,'+base64.b64encode(text.encode()).decode()
web=root/'web'
amounts=uri((web/'amounts.mjs').read_text())
model=uri((web/'report-model.mjs').read_text().replace('./amounts.mjs',amounts))
code=(web/'reporting.mjs').read_text().replace('./amounts.mjs',amounts).replace('./report-model.mjs',model)
html=re.sub(r'<script[^>]*>.*?</script>','',(web/'reports.html').read_text(),flags=re.S)
html=re.sub(r'<link[^>]*>','',html)
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,executable_path=args.chromium,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1050},device_scale_factor=1)
    errors=[];requests=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    page.on('request',lambda r:requests.append(r.url))
    page.expose_function('fixtureResponse',fixture)
    page.set_content(html)
    page.add_style_tag(content=(web/'reports.css').read_text())
    page.evaluate('''window.fetch=async path=>{const r=await window.fixtureResponse(path);return {ok:r.status===200,status:r.status,json:async()=>r.body};}''')
    page.add_script_tag(type='module',content=code)
    page.wait_for_selector('#report-table')
    assert page.locator('#result .metric').count()==4
    print('ledger loaded', page.locator('#selection-state').inner_text())
    screenshot(page,'ledger-desktop.png')
    page.locator('.chart-point').nth(1).focus();page.keyboard.press('Enter')
    assert 'date 2026-' in page.locator('.table-footer').inner_text()
    page.get_by_role('button',name='Clear chart filter').click()
    # An edited selection must remove export and charts immediately.
    page.fill('#account','missing')
    assert page.locator('#export').count()==0
    page.click('#run');page.wait_for_selector('#result .error')
    assert page.locator('#report-table').count()==0
    page.fill('#account','1000')
    page.evaluate("""window.originalFixtureFetch=window.fetch;
      window.heldReply=null;window.releaseReply=null;
      window.fetch=async path=>{const result=await window.originalFixtureFetch(path);
        if(String(path).startsWith('/api/ledger?')){window.heldReply=result;
          return await new Promise(resolve=>window.releaseReply=()=>resolve(result));}
        return result;};""")
    page.click('#run');page.wait_for_function('window.releaseReply!==null')
    page.fill('#account','1100')
    page.evaluate("window.releaseReply();window.fetch=window.originalFixtureFetch")
    page.wait_for_timeout(100)
    assert page.locator('#export').count()==0
    assert page.locator('#report-table').count()==0
    page.evaluate("location.hash='aging'")
    page.wait_for_selector('#report-table')
    assert '0–30 days' in page.locator('.chart').text_content()
    screenshot(page,'aging-desktop.png')
    page.locator('.chart g[role=button]').nth(2).focus();page.keyboard.press('Enter')
    assert '61–90 days' in page.locator('.table-footer').inner_text()
    page.get_by_role('button',name='Clear chart filter').click()
    page.select_option('select[aria-label="Open-item side"]','Debit')
    page.locator('.entry-link').first.click()
    page.wait_for_selector('#entry-body .document')
    assert 'Current entry/lineage observation' in page.locator('#entry-body').inner_text()
    page.keyboard.press('Escape')
    assert not page.locator('#entry-dialog').is_visible()
    # Capture exact export bytes without making a real download.
    page.evaluate('''window.exportedCsv=null; URL.createObjectURL=b=>{b.text().then(t=>window.exportedCsv=t);return 'blob:fixture-only';};HTMLAnchorElement.prototype.click=function(){};''')
    page.click('#export');page.wait_for_function('window.exportedCsv!==null')
    csv=page.evaluate('window.exportedCsv')
    assert '"demo"' in csv and '"aging"' in csv and '2026-09-30' in csv
    assert '"Credit"' not in csv
    page.click('#theme');assert page.locator('html').get_attribute('data-theme')=='dark'
    screenshot(page,'aging-dark.png')
    page.set_viewport_size({'width':390,'height':844})
    screenshot(page,'aging-mobile.png')
    overflow=page.evaluate('document.documentElement.scrollWidth>innerWidth')
    print('mobile overflow',overflow)
    assert not overflow
    page.emulate_media(media='print')
    assert page.locator('#demo-warning').is_visible()
    assert not errors, errors
    assert not requests, requests
    assert page.locator('body').evaluate('(n)=>getComputedStyle(n).backgroundColor')=='rgb(255, 255, 255)' 
    print('PASS: offline Chromium DOM, chart keyboard filters, selector invalidation, refusal, aging, entry drilldown, scoped CSV, theme, mobile, print. No browser network or native integration claimed.')
    browser.close()
