#!/usr/bin/env python3
"""Builds core/triage_seeds/<name>.json from an analyst's classification workbook (the proyecto-a .xlsx).

The workbook is the analyst's work: root-cause catalog + the per-occurrence classification (Detalle!N). This reads it with the stdlib only
(no openpyxl on the host) and turns the per-occurrence decisions into a SMALL rule set (rule / repo / file / line) so the same classification
can be applied to live findings by core/triage.py.

Conservative generalisation (so a NEW finding is never silently hidden as a false positive):
  * a rule whose every occurrence has the same root cause  -> one generic rule
  * an ambiguous rule whose dominant cause is NOT a false positive -> a generic rule for it + explicit exceptions
  * otherwise -> explicit per-file / per-line rules only; anything else stays SIN CLASIFICAR

usage: python3 scripts/build_triage_seed.py docs/proyecto-a_Hallazgos_Centinela_clasificados.xlsx gitlab2 grupo-a/proyecto-a "proyecto-a" core/triage_seeds/adem_proyecto-a.json
"""
import collections
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
UNLISTED = "(No listado en el PDF"
CLASS = {"V": "Vulnerabilidad", "F": "Falso positivo", "C": "Calidad"}


class Book:
    def __init__(self, path):
        self.z = zipfile.ZipFile(path)
        self.ss = ["".join(t.text or "" for t in si.iter("{%s}t" % NS["m"]))
                   for si in ET.fromstring(self.z.read("xl/sharedStrings.xml")).findall("m:si", NS)]
        self.wb = ET.fromstring(self.z.read("xl/workbook.xml"))
        self.rels = {r.get("Id"): r.get("Target") for r in ET.fromstring(self.z.read("xl/_rels/workbook.xml.rels"))}

    def formulas(self, name):
        """{row: {col: formula text}} -- only the cells that hold a formula."""
        for s in self.wb.find("m:sheets", NS):
            if s.get("name") == name:
                root = ET.fromstring(self.z.read("xl/" + self.rels[s.get("{%s}id" % NS["r"])]))
                out = {}
                for row in root.iter("{%s}row" % NS["m"]):
                    for c in row.findall("m:c", NS):
                        f = c.find("m:f", NS)
                        if f is not None and f.text:
                            out.setdefault(int(row.get("r")), {})[re.sub(r"\d", "", c.get("r"))] = f.text
                return out
        raise KeyError(name)

    def sheet(self, name):
        for s in self.wb.find("m:sheets", NS):
            if s.get("name") == name:
                root = ET.fromstring(self.z.read("xl/" + self.rels[s.get("{%s}id" % NS["r"])]))
                rows = {}
                for row in root.iter("{%s}row" % NS["m"]):
                    d = {}
                    for c in row.findall("m:c", NS):
                        v = c.find("m:v", NS)
                        if v is None and c.get("t") != "inlineStr":
                            continue
                        if c.get("t") == "s":
                            val = self.ss[int(v.text)]
                        elif c.get("t") == "inlineStr":
                            val = "".join(t.text or "" for t in c.iter("{%s}t" % NS["m"]))
                        else:
                            val = v.text
                        d[re.sub(r"\d", "", c.get("r"))] = val
                    rows[int(row.get("r"))] = d
                return rows
        raise KeyError(name)


def num(x, default=None):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def rule_key(display, engine):
    """(engine, regex) that matches the live cve_id for a workbook 'Regla' label."""
    if display.startswith("semgrep "):
        return "semgrep", re.escape(display[len("semgrep "):])
    return None, "^" + re.escape(display) + "$"


def build(path, instance, group_path, title):
    b = Book(path)
    causes = []
    for r, d in sorted(b.sheet("Vulnerabilidades").items()):
        if r >= 5 and d.get("A", "").startswith("V-"):
            causes.append(dict(code=d["A"], classification="Vulnerabilidad", title=d.get("B"), kind=d.get("C"), severity=d.get("D"),
                               certainty=d.get("E"), how_to_confirm=d.get("J"), strategy=d.get("K"), owner=d.get("L"),
                               outdated=d.get("M") == "Sí", rationale=None))
    for r, d in sorted(b.sheet("Falsos positivos").items()):
        if r >= 5 and d.get("A", "").startswith("FP-"):
            causes.append(dict(code=d["A"], classification="Falso positivo", title=d.get("B"), kind=d.get("C"), severity=None,
                               certainty=d.get("D"), rationale=d.get("I"), how_to_confirm=d.get("J"), strategy=None, owner=None,
                               outdated=d.get("K") == "Sí"))
    for r, d in sorted(b.sheet("Calidad").items()):
        if r >= 5 and d.get("A", "").startswith("C-"):
            causes.append(dict(code=d["A"], classification="Calidad", title=d.get("B"), kind=d.get("C"), severity=None, certainty=None,
                               rationale=d.get("H"), how_to_confirm=None, strategy=d.get("I"), owner=d.get("J"), outdated=False))
    by_code = {c["code"]: c for c in causes}

    plan_sheet = b.sheet("Plan de trabajo")
    plan_formulas = b.formulas("Plan de trabajo")
    params = dict(hours_per_day=num(plan_sheet[3].get("D"), 8), test_pct=num(plan_sheet[3].get("G"), 0.3),
                  fp_check_hours=num(plan_sheet.get(70, {}).get("F"), 0.5))
    areas = []
    for r in range(58, 62):
        d = plan_sheet[r]
        areas.append(dict(name=d["A"], people=num(d.get("H"), 1), dedication=num(d.get("I"), 1)))
    area_cols = ["T", "U", "V", "W"]
    for order, r in enumerate(sorted(k for k in plan_sheet if 6 <= k <= 32 and plan_sheet[k].get("B"))):
        d = plan_sheet[r]
        code = d["B"]
        # "Cantidad" is normally the number of unique occurrences; the analyst overrides it with a fixed number of work units for some causes
        # (e.g. 5 major-version upgrades), written as IF(COUNTIFS(...)>0,N,0)
        fq = re.match(r"^IF\(COUNTIFS\([^)]*\)>0,(\d+(?:\.\d+)?),0\)$", plan_formulas.get(r, {}).get("I", ""))
        by_code[code]["plan"] = dict(fixed_qty=float(fq.group(1)) if fq else None, 
            order=order + 1, phase=d.get("E"), activity=d.get("F"), unit=d.get("H"), minutes=num(d.get("J"), 0),
            minutes_source=d.get("K"), extra_hours=num(d.get("N"), 0), extra_text=d.get("O"), confirm_hours=num(d.get("P"), 0),
            area_pct=[num(d.get(c), 0) for c in area_cols],
            default_criticality=(d.get("D") if code.startswith("C-") and d.get("D") in ("Crítico", "Alto", "Medio", "Bajo") else None))
    # the criticality column of a quality cause is a formula; its default is encoded in the formula text, so read the cached value
    rows = []
    det = b.sheet("Detalle")
    for r, d in sorted(det.items()):
        if r == 1 or not d.get("N"):
            continue
        rows.append(d)

    # dedup scope: a cause whose workbook duplicates point at a DIFFERENT line of the same file (a Dockerfile, a pair of adjacent properties) is
    # deduplicated per file; everything else only when the very same line is reported by more than one engine.
    by_occ = {d["A"]: d for d in rows}
    for c in causes:
        c["dedup_scope"] = "line"
    for d in rows:
        keeper = by_occ.get(d.get("P"))
        if keeper and keeper.get("J") != d.get("J"):
            by_code[d["N"]]["dedup_scope"] = "file"
    # rule -> causes
    fam = collections.defaultdict(collections.Counter)
    for d in rows:
        eng, rx_ = rule_key(d["E"], d["D"])
        fam[(eng, rx_)][d["N"]] += 1
    rules = []
    generic = {}
    for (eng, rx_), cnt in fam.items():
        if len(cnt) == 1:
            code = next(iter(cnt))
            generic[(eng, rx_)] = code
        else:
            top, n = cnt.most_common(1)[0]
            if CLASS[top[0]] != "Falso positivo" and n * 2 >= sum(cnt.values()):
                generic[(eng, rx_)] = top
    for (eng, rx_), code in sorted(generic.items(), key=lambda x: str(x)):
        rules.append(dict(rule_regex=rx_, engine=eng, asset_regex=None, path_regex=None, line=None, root_cause_code=code, priority=0, note=None))
    # explicit exceptions / un-generalised rules
    pending = collections.defaultdict(list)
    for d in rows:
        eng, rx_ = rule_key(d["E"], d["D"])
        if generic.get((eng, rx_)) == d["N"]:
            continue
        if d.get("I", "").startswith(UNLISTED):
            continue
        pending[(eng, rx_, d["C"], d.get("I", ""), d["N"])].append(d)
    per_file = collections.defaultdict(set)  # ALL causes seen in a file for a rule, including the ones a generic rule already covers
    for d in rows:
        e_, r_ = rule_key(d["E"], d["D"])
        per_file[(e_, r_, d["C"], d.get("I", ""))].add(d["N"])
    for (eng, rx_, repo, f, code), ds in sorted(pending.items(), key=lambda x: str(x[0])):
        ambiguous_file = len(per_file[(eng, rx_, repo, f)]) > 1
        lines = sorted({int(x["J"]) for x in ds if x.get("J") and x["J"].isdigit()})
        notes = {x.get("O") for x in ds}
        note = next(iter(notes)) if len(notes) == 1 and next(iter(notes)) else None
        base = dict(rule_regex=rx_, engine=eng, asset_regex="/" + re.escape(repo) + "$", root_cause_code=code, note=note)
        path = "^" + re.escape(f) + "(:\\d+)?$" if f and not f.startswith("gitlab:") else None
        if f.startswith("gitlab:"):
            path = "^" + re.escape(f) + "$"
        if ambiguous_file and lines:
            for ln in lines:
                rules.append(dict(base, path_regex=path, line=ln, priority=20))
        else:
            rules.append(dict(base, path_regex=path, line=None, priority=10))
    return dict(group=dict(instance=instance, group_path=group_path, title=title, **params, areas=areas),
                root_causes=causes, rules=rules)


if __name__ == "__main__":
    src, inst, gpath, title, out = sys.argv[1:6]
    seed = build(src, inst, gpath, title)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(seed, fh, ensure_ascii=False, indent=1)
    print(f"{len(seed['root_causes'])} causas raíz, {len(seed['rules'])} reglas -> {out}")
