#!/usr/bin/env python3
"""
Starter-lineage report over the fleet (ADR-0012 D5). READ-ONLY. Run inside `centinela-ai` (it owns the clones under /tmp/centinela_gitlab_scans):
    docker exec -w /app centinela-ai python scripts/starter_lineage_report.py [--json] [--out data/reports/starter_lineage.json]

Answers: of the open findings in repositories that have a clone, how many sit in a file identical to the Starter Core (fix ONCE in the Starter),
in a file the project modified, or in the project's own code -- and which Starter files concentrate findings across many projects.
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, ".")
from auditors import starter_lineage as sl  # noqa: E402
from core import code_context, db_manager  # noqa: E402

WORKSPACE = "/tmp/centinela_gitlab_scans"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()

    dirs = sl.starter_dirs(WORKSPACE)
    configured = {"grupos": sl.starter_groups(), "proyectos_extra": sl.starter_projects()}
    if not dirs:
        msg = {"evaluable": False, "reason": f"ningún clon del Starter Core configurado ({configured}) en {WORKSPACE}"}
        print(json.dumps(msg, ensure_ascii=False, indent=2))
        return 0
    starter_idx = {name: sl.index_tree(path) for name, path in dirs.items()}

    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT i.asset_name, v.url_path, v.cve_id, COALESCE(v.real_severity, v.severity)
                       FROM vulnerability_log v JOIN infra_inventory i ON i.id=v.asset_id
                       WHERE i.asset_type='GitLab-Repo' AND v.finding_category='VULNERABILITY'
                         AND v.status NOT IN ('RESOLVED','SUPPRESSED') AND v.url_path IS NOT NULL""")
        rows = cur.fetchall()
    by_asset = defaultdict(list)
    for name, up, rule, sev in rows:
        by_asset[name].append({"url_path": up, "rule": rule, "severity": sev})

    state_count, per_file = Counter(), defaultdict(lambda: {"findings": 0, "projects": set(), "rules": Counter()})
    scanned, skipped, too_large = 0, [], []
    starter_names = set(dirs)
    for name, fs in by_asset.items():
        from core import gitlab_instances as gi
        _inst, _path, _branch = gi.parse_asset_name(name)
        if sl.is_starter_path(_path):
            continue                                            # the Starter's own repos are not "projects derived from it"
        if name.startswith(("Centinela-AI (Self-Audit)", "Self-Audit: ", "Local/")):
            continue                                            # not a GitLab clone of a project derived from the Starter (Self-Audit resolves to /app)
        repo = code_context._resolve_repo_dir(name, None, WORKSPACE)
        if not repo:
            skipped.append(name)
            continue
        try:
            lin = sl.classify_files(sl.index_tree(repo), starter_idx)
        except sl.TreeTooLarge as e:
            too_large.append(str(e))
            continue
        scanned += 1
        for f in sl.annotate_findings(fs, lin):
            st = f["lineage"]["state"]
            state_count[st] += 1
            if st == sl.INHERITED:
                key = f"{f['lineage']['starter']}:{f['lineage']['starter_path']}"
                pf = per_file[key]
                pf["findings"] += 1
                pf["projects"].add(name.split("@")[0])
                pf["rules"][f["rule"]] += 1
    top = sorted(({"starter_file": k, "findings": v["findings"], "projects": len(v["projects"]), "rules": dict(v["rules"].most_common(3))}
                  for k, v in per_file.items()), key=lambda d: (-d["projects"], -d["findings"]))[:25]
    result = {"evaluable": True, "starter_core": dirs, "starter_files": {n: len(i) for n, i in starter_idx.items()},
              "repos_compared": scanned, "repos_without_clone": len(skipped), "repos_too_large_not_compared": too_large, "findings_by_lineage": dict(state_count), "top_inherited_files": top,
              "limits": "comparación por archivo completo; el Starter Core es todo el grupo starters/ (STARTER_CORE_GROUPS) y se excluye de la comparación"}
    if a.out:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
