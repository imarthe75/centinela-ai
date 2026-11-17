"""
Registry of the GitLab instances Centinela audits.

Until 2026-10-01 the whole platform assumed exactly one GitLab (GITLAB_URL / GITLAB_TOKEN). A second
instance is configured with GITLAB2_URL / GITLAB2_TOKEN (GITLAB3_*, ... up to GITLAB9_* work the
same way). Everything that talks to GitLab resolves its URL/token/naming through here so a project
id, a clone path or an asset name from one instance can never be confused with another's:

  * project ids are only unique PER instance  -> every API call carries an instance key
  * asset names: primary keeps the historical "GitLab/<path>" (no data migration); the others use
    "GitLab2/<path>", "GitLab3/<path>", ... so equal paths on two instances stay distinct assets
  * clone folders: primary keeps "<path with / -> _>"; the others are prefixed "gitlab2__..."
  * the "only clone from a configured GitLab host" guard (project rule #7) validates against the
    resolved instance, never "any configured instance's token on any host"
"""
import hashlib
import os
import re
from typing import Dict, List, NamedTuple, Optional
from urllib.parse import urlparse

PRIMARY_KEY = "primary"
_DEFAULT_PRIMARY_URL = "http://192.0.2.14"


class GitLabInstance(NamedTuple):
    key: str          # "primary", "gitlab2", "gitlab3", ...
    url: str          # no trailing slash
    token: str
    asset_prefix: str  # "GitLab/" for primary, "GitLab2/" ...
    folder_prefix: str  # "" for primary, "gitlab2__" ...

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc.split("@")[-1].lower()

    def asset_name(self, path_with_namespace: str, branch: Optional[str] = None) -> str:
        """"GitLab/<path>" for the project's regular (default/develop) scan; "GitLab/<path>@<branch>" for a branch the
        user chose to audit on its own. A GitLab project path can never contain '@', so the first '@' is unambiguous."""
        base = f"{self.asset_prefix}{path_with_namespace}"
        return f"{base}@{branch}" if branch else base

    def clone_folder(self, path_with_namespace: str, branch: Optional[str] = None) -> str:
        base = f"{self.folder_prefix}{path_with_namespace.replace('/', '_')}"
        return f"{base}@{branch_slug(branch)}" if branch else base


def branch_slug(branch: str) -> str:
    """Filesystem-safe, collision-free folder/key fragment for a branch name ('feature/x' and 'feature_x' must differ)."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", branch).strip("_") or "branch"
    return f"{safe[:60]}-{hashlib.sha1(branch.encode()).hexdigest()[:6]}"


def configured_instances() -> List[GitLabInstance]:
    """Every instance with a URL configured, primary first. An instance with a URL but no token is
    still returned (public projects / read-only) -- callers already tolerate an empty token."""
    out: List[GitLabInstance] = []
    primary_url = (os.getenv("GITLAB_URL") or _DEFAULT_PRIMARY_URL).rstrip("/")
    out.append(GitLabInstance(PRIMARY_KEY, primary_url, os.getenv("GITLAB_TOKEN") or "", "GitLab/", ""))
    for n in range(2, 10):
        url = (os.getenv(f"GITLAB{n}_URL") or "").strip().rstrip("/")
        if url:
            out.append(GitLabInstance(f"gitlab{n}", url, os.getenv(f"GITLAB{n}_TOKEN") or "",
                                      f"GitLab{n}/", f"gitlab{n}__"))
    return out


def get_instance(key: Optional[str] = None) -> GitLabInstance:
    """Instance by key ("primary" when None/empty). Raises KeyError for an unconfigured key so a
    typo can never silently fall back to the primary instance's credentials."""
    wanted = (key or PRIMARY_KEY).lower()
    for inst in configured_instances():
        if inst.key == wanted:
            return inst
    raise KeyError(f"GitLab instance '{key}' is not configured (known: {[i.key for i in configured_instances()]})")


def instance_for_host(url_or_host: str) -> Optional[GitLabInstance]:
    """Instance whose host matches the given URL/host, or None. Used to attribute a webhook payload
    to an instance without trusting anything else in it."""
    raw = str(url_or_host or "")
    host = (urlparse(raw).netloc if "://" in raw else raw).split("@")[-1].lower()
    for inst in configured_instances():
        if inst.host == host:
            return inst
    return None


def instance_for_asset_name(asset_name: str) -> Optional[GitLabInstance]:
    """Instance an asset belongs to, from its name prefix (longest prefix first so 'GitLab2/' is
    never mistaken for 'GitLab/')."""
    name = str(asset_name or "")
    for inst in sorted(configured_instances(), key=lambda i: -len(i.asset_prefix)):
        if name.startswith(inst.asset_prefix):
            return inst
    return None


def parse_asset_name(asset_name: str):
    """(instance, path_with_namespace, branch|None) for a GitLab asset name, branch assets included.
    instance is None when the name belongs to no configured instance."""
    inst = instance_for_asset_name(asset_name)
    rest = asset_name[len(inst.asset_prefix):] if inst else str(asset_name or "")
    path, sep, branch = rest.partition("@")
    return inst, path, (branch if sep and branch else None)


def strip_asset_prefix(asset_name: str) -> str:
    """Project path of an asset name (without the instance prefix and without any '@branch' suffix)."""
    return parse_asset_name(asset_name)[1]


def describe() -> List[Dict[str, str]]:
    """Safe-to-log summary (never includes the token)."""
    return [{"key": i.key, "url": i.url, "asset_prefix": i.asset_prefix, "has_token": bool(i.token)}
            for i in configured_instances()]


SCAN_EXCLUDE_FILE = os.getenv("GITLAB_SCAN_EXCLUDE_FILE", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                                                        "config", "gitlab_scan_exclude.txt"))


def scan_exclusions(path: Optional[str] = None) -> List[str]:
    """Entries of the scan-exclusion file ("GitLab2/grupo-b/proyecto-i", or "GitLab2/grupo-b/grupo/" for a whole group). Re-read on every
    call so editing the file takes effect on the next cycle without a restart. A missing file means no exclusions."""
    try:
        with open(path or SCAN_EXCLUDE_FILE, encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    except FileNotFoundError:
        return []


def is_scan_excluded(instance: GitLabInstance, path_with_namespace: str, exclusions: Optional[List[str]] = None) -> bool:
    """True when the owner excluded this project (or its group) from periodic scanning. Matching is exact on the project path, or a
    prefix only for an entry ending in '/', so excluding 'proyecto-i' never silently excludes 'proyecto-i-demo-template'."""
    name = instance.asset_name(path_with_namespace or "").lower()
    for entry in (scan_exclusions() if exclusions is None else exclusions):
        e = entry.lower()
        if (e.endswith("/") and name.startswith(e)) or name == e:
            return True
    return False
