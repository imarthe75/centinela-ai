#!/usr/bin/env python3
"""Populate asset_auth_roles for every GitLab-Repo asset that has a local clone (the periodic scan keeps it fresh afterwards).
Run inside centinela-ai:  docker exec centinela-ai python3 scripts/discover_roles_fleet.py"""
import logging
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from auditors import role_discovery
from core import db_manager
from core.code_context import _resolve_repo_dir, DEFAULT_SCAN_WORKSPACE

logging.basicConfig(level=logging.INFO)
done = with_roles = 0
with db_manager.get_db_cursor() as cur:
    cur.execute("SELECT id, asset_name FROM public.infra_inventory WHERE asset_type = 'GitLab-Repo' ORDER BY asset_name")
    assets = cur.fetchall()
for asset_id, name in assets:
    root = _resolve_repo_dir(name, None, DEFAULT_SCAN_WORKSPACE)
    if not root:
        continue
    roles = role_discovery.discover_roles(root)
    with db_manager.get_db_cursor() as cur:
        role_discovery.persist_roles(cur, str(asset_id), roles)
    done += 1
    with_roles += bool(roles)
    if roles:
        print(f"{len(roles):3d} profiles  {name}")
print(f"assets with a clone: {done}; with at least one profile: {with_roles}; total assets: {len(assets)}")
