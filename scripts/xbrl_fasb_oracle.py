"""Check fully reported monetary sums in native XBRL exports against FASB's 2026 taxonomy."""

import argparse
from collections import defaultdict
from datetime import date
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from zipfile import ZipFile


RELEASE_URL = "https://xbrl.fasb.org/us-gaap/2026/us-gaap-2026.zip"
RELEASE_SHA256 = "f4c8b8b5697ba7d825a8614b159611cd25a46640e98a9737cda1e4a672bd4c81"
TAXONOMY = "{http://fasb.org/us-gaap/2026}"
XSD = "{http://www.w3.org/2001/XMLSchema}"
INSTANCE = "{http://www.xbrl.org/2003/instance}"
LINK = "{http://www.xbrl.org/2003/linkbase}"
XLINK = "{http://www.w3.org/1999/xlink}"
ISO4217 = "http://www.xbrl.org/2003/iso4217"


def published_taxonomy(package):
    data = package.read_bytes()
    if hashlib.sha256(data).hexdigest() != RELEASE_SHA256:
        raise ValueError(f"expected the original 2026 FASB archive with SHA-256 {RELEASE_SHA256}")
    with ZipFile(io.BytesIO(data)) as archive:
        def member(path):
            return ET.fromstring(archive.read("us-gaap-2026/" + path))

        schema = member("elts/us-gaap-2026.xsd")
        concepts = {element.attrib["name"]: element.attrib[INSTANCE + "periodType"]
                    for element in schema.findall(XSD + "element")
                    if element.get("type") == "xbrli:monetaryItemType"
                    and element.get("abstract") != "true"}
        roles = {}
        for filename in ("stm/us-gaap-stm-sfp-cls-cal-2026.xml", "stm/us-gaap-stm-soi-cal-2026.xml"):
            for network in member(filename).findall(LINK + "calculationLink"):
                locators = {loc.attrib[XLINK + "label"]: loc.attrib[XLINK + "href"].split("#us-gaap_")[1]
                            for loc in network.findall(LINK + "loc")}
                families = defaultdict(dict)
                for arc in network.findall(LINK + "calculationArc"):
                    parent = locators[arc.attrib[XLINK + "from"]]
                    child = locators[arc.attrib[XLINK + "to"]]
                    families[parent][child] = Fraction(arc.attrib["weight"])
                roles[network.attrib[XLINK + "role"]] = families
    return concepts, roles


def native_document(data):
    namespaces = {}
    parser = ET.iterparse(io.BytesIO(data), events=("start-ns", "start"))
    root_seen = False
    for event, value in parser:
        if event == "start-ns":
            if root_seen:
                raise ValueError("native exports declare their namespaces on the root")
            prefix, uri = value
            namespaces[prefix] = uri
        else:
            root_seen = True
    if parser.root.tag != INSTANCE + "xbrl":
        raise ValueError("expected an XBRL instance root")
    return parser.root, namespaces


def context_type(context):
    period = context.find(INSTANCE + "period")
    if period is None:
        raise ValueError("missing period in context " + context.attrib["id"])
    tags = [node.tag for node in period]
    if tags == [INSTANCE + "instant"]:
        kind = "instant"
    elif tags == [INSTANCE + "startDate", INSTANCE + "endDate"]:
        kind = "duration"
    else:
        raise ValueError("unrecognized period in context " + context.attrib["id"])
    dates = [date.fromisoformat(node.text or "") for node in period]
    if dates[0] > dates[-1]:
        raise ValueError("reversed period in context " + context.attrib["id"])
    return kind


def indexed(elements):
    result = {}
    for element in elements:
        key = element.attrib["id"]
        if key in result:
            raise ValueError(f"duplicate identifier {key}")
        result[key] = element
    return result


def monetary_facts(data, concepts):
    root, namespaces = native_document(data)
    contexts = {key: context_type(element)
                for key, element in indexed(root.findall(INSTANCE + "context")).items()}
    units = indexed(root.findall(INSTANCE + "unit"))
    currencies = {}
    for key, unit in units.items():
        if key in contexts or [node.tag for node in unit] != [INSTANCE + "measure"]:
            raise ValueError(f"invalid monetary unit {key}")
        prefix, _, currency = (unit[0].text or "").partition(":")
        if namespaces.get(prefix) != ISO4217 or not re.fullmatch("[A-Z]{3}", currency):
            raise ValueError(f"invalid monetary measure for {key}")
        currencies[key] = currency
    groups = defaultdict(dict)
    for item in root:
        if item.tag in (INSTANCE + "context", INSTANCE + "unit", LINK + "schemaRef"):
            continue
        name = item.tag.removeprefix(TAXONOMY)
        if name == item.tag or name not in concepts:
            raise ValueError(f"unrecognized monetary concept {item.tag}")
        context, unit = item.attrib["contextRef"], item.attrib["unitRef"]
        if contexts.get(context) != concepts[name] or unit not in units:
            raise ValueError(f"invalid period or unit for {name} in {context}, {unit}")
        if len(item) or not re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", item.text or ""):
            raise ValueError(f"expected an exact monetary amount for {name}")
        amount = Fraction(item.text)
        group = groups[context, unit, currencies[unit]]
        if name in group and group[name] != amount:
            raise ValueError(f"conflicting amounts for {name} in {context}, {unit}")
        group[name] = amount
    return groups


def compare(data, concepts, roles, required):
    groups = monetary_facts(data, concepts)
    complete, incomplete = [], []
    for (context, unit, currency), facts in groups.items():
        for role, families in roles.items():
            for parent in sorted(facts.keys() & families.keys()):
                children = families[parent]
                row = dict(parent=parent, role=role, context=context, unit_ref=unit, currency=currency)
                missing = sorted(children.keys() - facts.keys())
                if missing:
                    incomplete.append(dict(**row, missing_children=missing))
                    continue
                total = sum(weight * facts[child] for child, weight in children.items())
                complete.append(dict(**row, reported=str(facts[parent]), computed=str(total),
                                     exact=facts[parent] == total,
                                     contributors={c: {"weight": str(w), "value": str(facts[c])}
                                                   for c, w in sorted(children.items())}))
    missing_required = sorted(required - {row["parent"] for row in complete})
    if missing_required or any(not row["exact"] for row in complete):
        status = "FAIL"
    else:
        status = "PASS" if complete else "UNRUN"
    return dict(status=status, sha256=hashlib.sha256(data).hexdigest(),
                distinct_facts=sum(map(len, groups.values())), complete=complete,
                incomplete=incomplete, missing_required=missing_required)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--taxonomy", type=Path, required=True, help="original US-GAAP 2026 ZIP")
    parser.add_argument("--require", action="append", default=[], metavar="PARENT",
                        help="require a complete calculation for this local concept in each file")
    parser.add_argument("instances", nargs="+", type=Path)
    args = parser.parse_args()
    report = dict(source=RELEASE_URL, taxonomy_sha256=RELEASE_SHA256, instances=[])
    try:
        concepts, roles = published_taxonomy(args.taxonomy)
    except (OSError, ValueError) as error:
        report.update(status="UNRUN", error=str(error))
    else:
        for path in args.instances:
            try:
                result = compare(path.read_bytes(), concepts, roles, set(args.require))
            except OSError as error:
                result = dict(status="UNRUN", error=str(error))
            except (ET.ParseError, ValueError, KeyError) as error:
                result = dict(status="FAIL", error=str(error))
            report["instances"].append(dict(path=str(path), **result))
        statuses = {result["status"] for result in report["instances"]}
        report["status"] = next(status for status in ("FAIL", "UNRUN", "PASS") if status in statuses)
    print(json.dumps(report, indent=2, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "UNRUN": 4}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
