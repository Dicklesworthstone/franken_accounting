"""Offline Chromium interaction test of the actual workbench with synthetic data.

No browser network request is made. This is NOT a native-book integration test,
HTTP/CSP/bootstrap test, or accessibility certification. Playwright and Chromium
are optional test tools, not dashboard runtime dependencies.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serve import DashboardError, exact_transport
from demo import DemoSource
import reports

WEB = Path(__file__).resolve().parents[1] / "web"
SOURCE = DemoSource(DashboardError)


def fixture_read(url):
    target = urlsplit(url)
    params = {key: value[0] for key, value in parse_qs(target.query).items()}
    try:
        if target.path in reports.ROUTES:
            result = reports.dispatch(SOURCE, target.path, params, DashboardError)
        elif target.path == "/api/bootstrap":
            result = SOURCE.bootstrap()
        elif target.path == "/api/overview":
            result = SOURCE.overview(params["period"], params["known_at"])
        elif target.path == "/api/account":
            result = SOURCE.account(params["account"], params["period"], params["known_at"])
        elif target.path == "/api/entry":
            result = SOURCE.entry(params["vid"])
        elif target.path == "/api/health":
            result = SOURCE.health()
        elif target.path == "/api/projections":
            result = SOURCE.projections()
        else:
            raise DashboardError("Unknown synthetic fixture route", 404)
        return {"status": 200, "body": exact_transport({"schema": "fa-dashboard/v1", "read_only": True,
                "mode": "demo", "title": "Northstar Studio · sample book", **result})}
    except DashboardError as error:
        return {"status": error.status, "body": {"error": str(error), "detail": error.detail}}


def code(name):
    # Preserve implementation bodies, isolate lexical module scopes, and remove
    # imports only for this offline test. Actual deployment serves ESM normally.
    return re.sub(r"^export ", "", re.sub(r"^import .*;\n", "", (WEB/name).read_text(), flags=re.M), flags=re.M)


def bundle():
    money = "parseAmount,zero,add,negate,subtract,compare,sum,format,ratio,csvCell,nativeRows,categoryNet"
    report = "requireThat,dayNumber,bandLabel,envelope,ledgerModel,agingModel,reportCsv,requestGate"
    model = "sequence,snapshot,stockRows,comparisonModel,comparisonCsv,accountGraph,entryGraph"
    layout = "layoutGraph,graphBounds"
    return ("const Money=(()=>{" + code("amounts.mjs") + ";return {" + money + "};})();\n" +
        "const Report=(()=>{const {parseAmount,add,subtract,compare,zero,ratio,csvCell}=Money;" + code("report-model.mjs") + ";return {" + report + "};})();\n" +
        "const Models=(()=>{const {parseAmount,zero,subtract,compare,format,csvCell}=Money;const {requireThat:check,dayNumber}=Report;" + code("workbench-model.mjs") + ";return {" + model + "};})();\n" +
        "const Layout=(()=>{" + code("graph-layout.mjs") + ";return {" + layout + "};})();\n" +
        "(()=>{const {parseAmount,zero,add,subtract,compare,sum,format,ratio,csvCell,categoryNet}=Money;const {ledgerModel,agingModel,bandLabel,reportCsv,requestGate,dayNumber}=Report;const {" + model + "}=Models;const {" + layout + "}=Layout;" + code("workbench.mjs") + "})();")


def mount(page):
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("request", lambda request: errors.append("UNEXPECTED NETWORK: " + request.url))
    html = re.sub(r"<script[^>]*>.*?</script>", "", (WEB/"index.html").read_text(), flags=re.S)
    html = re.sub(r"<link[^>]*>", "", html)
    page.set_content(html)
    page.add_style_tag(content=(WEB/"workbench.css").read_text())
    page.expose_function("fixtureRead", fixture_read)
    page.evaluate("""() => {
        // about:blank has no app/storage origin. This does not test routing.
        history.replaceState=(_state,_unused,url)=>{window.fixtureLocation=url};
        window.fetch=async(url)=>{
            const reply=await window.fixtureRead(url);
            if(window.holdNext&&url.includes(window.holdNext)){
                window.holdNext=null;
                await new Promise(resolve=>{window.releaseFixture=resolve});
            }
            return {ok:reply.status===200,status:reply.status,json:async()=>reply.body};
        };
        const createURL=URL.createObjectURL.bind(URL);
        URL.createObjectURL=blob=>{window.lastFixtureExport=blob;return createURL(blob)};
        document.addEventListener('click',e=>{if(e.target.closest('a[download]'))e.preventDefault()},true);
    }""")
    page.add_script_tag(content=bundle())
    return errors


def run(page, screenshots):
    def nav(view):
        page.locator('#navigation [data-view="'+view+'"]').click()

    def shot(name):
        if screenshots:
            page.wait_for_timeout(400)
            page.screenshot(path=str(screenshots/(name+".png")), full_page=True)

    errors = mount(page)
    page.locator("#spotlight-trail .trail-counts").wait_for(timeout=15000)
    assert page.locator(".metric-number").first.inner_text() == "702,910.00"
    assert page.locator("#demo-banner").is_visible()
    shot("workbench-overview")

    nav("compare")
    page.locator(".snapshot-pair").wait_for()
    page.get_by_label("Snapshot A", exact=True).fill("151")
    assert page.locator(".snapshot-pair").count() == 0
    assert page.get_by_role("button", name="Export comparison", exact=True).count() == 0
    page.locator("#scope-form").evaluate("n=>n.requestSubmit()")
    page.locator(".snapshot-pair").wait_for()
    assert "#151" in page.locator(".snapshot-pair").inner_text()
    assert page.locator(".comparison-table tbody tr").count() == 8
    shot("workbench-time-lens")
    page.get_by_role("button", name="Export comparison", exact=True).click()
    text = page.evaluate("window.lastFixtureExport.text()")
    assert '"demo"' in text and '"151","157"' in text and '"before_present"' in text
    page.locator(".comparison-table tbody tr").first.locator("button").click()
    assert "100,700.00" in page.locator("#inspector-content").inner_text()
    page.keyboard.press("Escape")

    # An in-flight old result cannot reappear after the scope has been edited.
    page.get_by_label("Snapshot A", exact=True).fill("152")
    page.evaluate("window.holdNext='/api/compare'")
    page.locator("#scope-form").evaluate("n=>n.requestSubmit()")
    page.wait_for_function("typeof window.releaseFixture==='function'")
    page.get_by_label("Snapshot A", exact=True).fill("153")
    page.evaluate("window.releaseFixture()")
    page.wait_for_timeout(150)
    assert page.locator(".snapshot-pair").count() == 0
    assert "not yet applied" in page.locator("#snapshot-status").inner_text()
    page.get_by_label("Snapshot A", exact=True).fill("999999")
    page.locator("#scope-form").evaluate("n=>n.requestSubmit()")
    page.locator(".error-panel").wait_for()
    assert page.get_by_role("button", name="Export comparison", exact=True).count() == 0

    nav("graph")
    page.locator('.graph-svg[data-settled="true"]').wait_for()
    assert page.locator(".graph-node").count() == 9
    assert page.locator(".graph-node.dimmed").count() == 0
    shot("workbench-graph")
    viewport = page.locator(".graph-svg").get_attribute("viewBox")
    page.get_by_role("button", name="Zoom in", exact=True).click()
    assert page.locator(".graph-svg").get_attribute("viewBox") != viewport
    page.get_by_role("button", name="Fit graph", exact=True).click()
    node = page.locator(".graph-node.entry").first
    before = node.get_attribute("transform")
    bounds = node.bounding_box()
    x, y = bounds["x"]+bounds["width"]/2, bounds["y"]+bounds["height"]/2
    page.mouse.move(x,y)
    page.mouse.down()
    page.mouse.move(x+45,y-24,steps=5)
    page.mouse.up()
    assert node.get_attribute("transform") != before
    node.focus()
    page.keyboard.press("Enter")
    assert "Pinned #157" in page.locator(".graph-inspector").inner_text()
    page.get_by_role("button", name="Inspect current entry", exact=True).click()
    page.locator("#inspector .tab-bar").wait_for()
    page.locator("#inspector").get_by_role("button", name="Evidence", exact=True).click()
    assert page.locator("#inspector .document-card").count() == 1
    shot("workbench-evidence-inspector")
    page.get_by_role("button", name="Explore entry graph", exact=True).click()
    page.locator('.graph-svg[data-settled="true"]').wait_for()
    assert page.locator("#scope-form").is_hidden()
    assert "Current inspection" in page.locator("#snapshot-status").inner_text()
    page.get_by_role("button", name="List", exact=True).click()
    assert page.locator(".graph-list").is_visible()
    page.get_by_label("Find a graph object", exact=True).fill("Invoice")
    assert page.locator(".graph-list button").count() == 1
    page.get_by_role("button", name="Return to account context", exact=True).click()
    page.locator('.graph-svg[data-settled="true"]').wait_for()
    assert page.locator("#scope-form").is_visible()

    nav("ledger")
    page.locator(".balance-chart").wait_for()
    assert page.locator(".metric-number").last.inner_text() == "592,010.00"
    page.locator(".chart-node").nth(1).focus()
    page.keyboard.press("Enter")
    assert "2026-09-05" in page.locator("#content").inner_text()
    page.get_by_role("button", name="Clear date filter", exact=True).click()
    shot("workbench-ledger")

    nav("aging")
    page.locator(".aging-band-grid").wait_for()
    page.get_by_label("Account", exact=True).fill("1100")
    page.locator("#scope-form").evaluate("n=>n.requestSubmit()")
    page.locator(".aging-band-grid").wait_for()
    assert page.locator(".metric-number").first.inner_text() == "733,500.00"
    page.locator(".aging-band").first.click()
    assert page.locator("tbody tr").count() == 2
    page.get_by_role("button", name="Clear band", exact=True).click()
    shot("workbench-aging")
    page.locator("#theme-button").click()
    assert page.locator("html").get_attribute("data-theme") == "dark"
    shot("workbench-aging-dark")

    page.keyboard.press("Control+k")
    page.locator("#command-input").fill("1100")
    page.keyboard.press("Enter")
    page.locator("#inspector .detail-grid").wait_for()
    assert "Trade receivables" in page.locator("#inspector-title").inner_text()
    page.keyboard.press("Escape")

    page.set_viewport_size({"width":390,"height":844})
    assert not page.evaluate("document.documentElement.scrollWidth>innerWidth")
    shot("workbench-mobile")
    page.locator("#mobile-command-button").click()
    assert page.locator("#command-dialog").is_visible()
    page.keyboard.press("Escape")
    page.emulate_media(media="print")
    assert page.locator("#demo-banner").is_visible()
    page.emulate_media(media="screen",reduced_motion="reduce")
    nav("graph")
    page.locator('.graph-svg[data-settled="true"]').wait_for()
    assert not page.evaluate("document.documentElement.scrollWidth>innerWidth")
    assert not errors, errors
    print("PASS: offline workbench interactions, source-scoped comparisons, late-response refusal, graph drag/zoom/list/inspector, exact exports, keyboard search, dark/mobile/print/reduced-motion. No browser network requests or JS errors.")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium",required=True,type=Path)
    parser.add_argument("--screenshots",type=Path)
    args=parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True,exist_ok=True)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=str(args.chromium),headless=True)
        try:
            page=browser.new_page(viewport={"width":1512,"height":1040},device_scale_factor=1)
            run(page,args.screenshots)
        finally:
            browser.close()


if __name__=="__main__":
    main()
