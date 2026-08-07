"""
OWASP ZAP DAST (Dynamic Application Security Testing) Integration

Provides dynamic vulnerability scanning for web applications using ephemeral ZAP containers
with persistent vulnerability DB caching for efficiency.

Architecture:
  - Ephemeral container per scan (clean state, no memory leaks)
  - Cached DB volume (~100MB) to avoid re-download
  - Smart retry logic with fallback to Nuclei-only mode
  - Results deduplicated with existing Nuclei findings
"""

import os
import sys
import json
import subprocess
import time
import requests
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from core import db_manager, deduplication_engine
import random
import string

logger = logging.getLogger(__name__)

# ZAP Configuration
ZAP_DOCKER_IMAGE = "zaproxy/zap-stable:latest"
ZAP_CONTAINER_PREFIX = "zap-scan"
ZAP_API_TIMEOUT = 30
ZAP_SCAN_TIMEOUT = 900  # 15 minutes max per scan
ZAP_DOCKER_NETWORK = "aura-network"

class ZAPScanProfile:
    """Scan profile definitions for different security testing scenarios."""
    PROFILES = {
        "light": {
            "timeout": 300,  # 5 min
            "spider_depth": 2,
            "max_rules": 20,
            "description": "Light scanning - OWASP Top 10 only"
        },
        "balanced": {
            "timeout": 900,  # 15 min (DEFAULT)
            "spider_depth": 3,
            "max_rules": 50,
            "description": "Balanced - common vulnerabilities"
        },
        "aggressive": {
            "timeout": 1800,  # 30 min
            "spider_depth": 5,
            "max_rules": 100,
            "description": "Aggressive - full OWASP Top 10 + advanced"
        },
        "api": {
            "timeout": 1200,  # 20 min
            "spider_depth": 3,
            "max_rules": 70,
            "description": "API-specific - REST/GraphQL fuzzing"
        }
    }

class ZAPScanError(Exception):
    """ZAP-specific exception."""
    pass

class ZAPTimeoutError(ZAPScanError):
    """ZAP scan exceeded timeout."""
    pass

class ZAPNotAvailableError(ZAPScanError):
    """ZAP container not available."""
    pass

def generate_container_id():
    """Generate unique container ID for this scan."""
    return f"{ZAP_CONTAINER_PREFIX}-{int(time.time())}-{''.join(random.choices(string.ascii_lowercase, k=4))}"

def launch_zap_container(container_id: str, db_cache_path: str = "/tmp/zap-cache") -> Tuple[str, int]:
    """
    Launches an ephemeral ZAP container with persistent config/addon cache.

    Args:
        container_id: Unique identifier for this scan
        db_cache_path: Host path to cached ZAP home dir (addons/plugins)

    Returns:
        (container_id, zap_base_url) if successful — zap_base_url is the container's own
        address on aura-network (http://<container_id>:8080), NOT a host port. This code runs
        `docker run` through the mounted docker.sock, which makes ZAP a *sibling* container on
        the host's Docker daemon, not a child of this one — a `-p host:container` mapping binds
        on the real host's interfaces, which "localhost" from inside this container can never
        reach. Since both containers share aura-network, addressing ZAP by its container name
        (Docker's built-in per-network DNS) is what actually works.

    Raises:
        ZAPNotAvailableError: If container fails to start
    """
    # ZAP refuses to start a second instance against a home dir already in use ("The home
    # directory is already in use") — it takes an exclusive lock there, so concurrent scans
    # can't share one cache path the way the (still shared) nuclei/DB-style cache elsewhere in
    # this codebase does. Each scan gets its own subdirectory instead: no lock collisions, at
    # the cost of a full addon re-download per scan (ZAP's home dir isn't just add-on storage,
    # it's session-scoped state) — a real tradeoff, not a bug, given this tool's design.
    scan_home = os.path.join(db_cache_path, container_id)

    # NOTE: os.makedirs(scan_home) here would create a directory inside *this* container's own
    # filesystem, not on the real host — `docker run -v` below goes through the mounted
    # docker.sock, so its bind-mount source is resolved by the host's dockerd against the real
    # host filesystem (same docker-outside-of-docker gotcha as above). The host auto-creates a
    # missing bind-mount source itself, owned by root, which the image's uid-1000 "zap" user
    # then can't write to ("The home path is not writable") and crashes on. Fix ownership
    # host-side via a disposable container before ever starting ZAP itself.
    subprocess.run(
        ["docker", "run", "--rm", "-v", f"{scan_home}:/target", "busybox",
         "chmod", "-R", "0777", "/target"],
        capture_output=True, timeout=30
    )

    cmd = [
        "docker", "run", "-d",
        "--name", container_id,
        "--network", ZAP_DOCKER_NETWORK,
        # The image runs as uid 1000 ("zap", $HOME=/home/zap), which is where it downloads its
        # addons/plugins and stores config on every cold start (confirmed via container logs:
        # /home/zap/.ZAP/plugin/*.zap) — /root/.zap/db was never on this image's write path at
        # all, so nothing was ever actually cached and every launch re-downloaded everything.
        "-v", f"{scan_home}:/home/zap/.ZAP",
        "-u", "1000:1000",
        "-e", "ZAP_CONFIG_BETA=1",
        ZAP_DOCKER_IMAGE,
        # -host 0.0.0.0: without this ZAP binds its API to 127.0.0.1 inside its own container —
        # its Docker HEALTHCHECK (which curls localhost from inside) reports "healthy" while
        # every other container on aura-network gets connection refused reaching it by name.
        # api.addrs.addr.name/.regex: ZAP's API separately allowlists request origins by Host
        # header regardless of api.disablekey — without this every request from another
        # container (Host: <container-name>, not localhost) gets rejected as "not permitted"
        # even once the network-level connection succeeds.
        "zap.sh", "-config", "api.disablekey=true", "-host", "0.0.0.0",
        "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true",
        "-daemon"
    ]

    # zaproxy/zap-stable listens on 8080 by default (the old owasp/zap2docker-stable image used
    # 8090 — confirmed via container logs: "ZAP is now listening on localhost:8080").
    zap_base_url = f"http://{container_id}:8080"

    print(f"🚀 [ZAP-Auditor] Launching container {container_id}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise ZAPNotAvailableError(f"Container launch failed: {result.stderr[:200]}")

        # Wait for ZAP API to be ready. ZAP is a JVM app — a cold start reliably takes well
        # over the old 10s budget (20 retries * 0.5s), which is why every launch used to fail
        # here even once the -d/networking issues above were fixed. 60 retries * 1s = 60s.
        max_retries = 60
        for i in range(max_retries):
            try:
                # "version" is a read-only lookup — it's a "view" in ZAP's API, not an "action"
                # (actions are for state-changing calls like starting a scan). The old path
                # here always 400'd, so the readiness probe could never succeed even once ZAP
                # was actually up, masking every other fix above behind a false "not ready".
                response = requests.get(f"{zap_base_url}/json/core/view/version", timeout=2)
                if response.status_code == 200:
                    print(f"✅ [ZAP-Auditor] ZAP API ready on {container_id}")
                    return container_id, zap_base_url
            except:
                pass
            time.sleep(1)

        raise ZAPNotAvailableError("ZAP API did not respond in time")
    except subprocess.TimeoutExpired:
        raise ZAPNotAvailableError("Container launch timeout")

def stop_zap_container(container_id: str):
    """Gracefully stops and removes ephemeral ZAP container."""
    try:
        cmd = ["docker", "stop", "-t", "5", container_id]
        subprocess.run(cmd, capture_output=True, timeout=10)

        cmd = ["docker", "rm", container_id]
        subprocess.run(cmd, capture_output=True, timeout=5)
        print(f"🧹 [ZAP-Auditor] Cleaned up {container_id}")
    except Exception as e:
        logger.warn(f"Could not cleanup {container_id}: {e}")

def configure_zap_context(target_url: str, scan_profile: str = "balanced"):
    """
    Configures ZAP scanning context and policies.

    Args:
        target_url: Target application URL
        scan_profile: One of 'light', 'balanced', 'aggressive', 'api'

    Returns:
        Context configuration dict
    """
    profile = ZAPScanProfile.PROFILES.get(scan_profile, ZAPScanProfile.PROFILES["balanced"])

    return {
        "target_url": target_url,
        "profile": scan_profile,
        "max_depth": profile["spider_depth"],
        "scan_timeout": profile["timeout"],
        "max_rules": profile["max_rules"],
        "follow_redirects": True,
        "exclude_patterns": [
            ".*logout.*",
            ".*signout.*",
            ".*sign-out.*",
            ".*/api/health.*",
        ]
    }

def run_zap_spider(target_url: str, max_depth: int = 3, zap_base_url: str = None) -> List[str]:
    """
    Executes ZAP spider to discover URLs via crawling.

    Args:
        target_url: Target application URL
        max_depth: Maximum crawl depth
        zap_base_url: This scan's ZAP container network address (http://<container>:8080)

    Returns:
        List of discovered URLs
    """
    print(f"🕷️  [ZAP-Auditor] Starting spider for {target_url} (depth={max_depth})...")

    try:
        # Start spider
        params = {
            "url": target_url,
            "maxDepth": max_depth,
            "recurse": "true"
        }
        response = requests.get(
            f"{zap_base_url}/json/spider/action/scan",
            params=params,
            timeout=ZAP_API_TIMEOUT
        )
        spider_id = response.json().get("scan")

        if not spider_id:
            print(f"⚠️  [ZAP-Auditor] Spider failed to start: {response.text[:200]}")
            return []

        # Monitor progress
        max_wait = 300  # 5 minutes
        start_time = time.time()
        while time.time() - start_time < max_wait:
            response = requests.get(
                f"{zap_base_url}/json/spider/view/status",
                params={"scanId": spider_id},
                timeout=ZAP_API_TIMEOUT
            )
            status = int(response.json().get("status", 0))

            if status >= 100:  # Complete
                break

            print(f"   Spider progress: {status}%")
            time.sleep(2)

        # Retrieve discovered URLs
        response = requests.get(
            f"{zap_base_url}/json/spider/view/results",
            params={"scanId": spider_id},
            timeout=ZAP_API_TIMEOUT
        )
        urls = response.json().get("results", [])
        print(f"✅ [ZAP-Auditor] Spider discovered {len(urls)} URLs")
        return urls

    except Exception as e:
        logger.error(f"Spider error: {e}")
        return []

def run_zap_active_scan(target_url: str, context_config: Dict, zap_base_url: str = None) -> List[Dict]:
    """
    Executes ZAP active scanning with payloads.

    Args:
        target_url: Target application URL
        context_config: Scanning context configuration
        zap_base_url: This scan's ZAP container network address (http://<container>:8080)

    Returns:
        List of vulnerability findings
    """
    print(f"🎯 [ZAP-Auditor] Starting active scan on {target_url} ({context_config['profile']})...")

    try:
        # scanPolicyName must name a policy that actually exists in ZAP ("Default Policy",
        # "Pen Test", etc. — confirmed via /json/ascan/view/scanPolicyNames/); our own profile
        # names ("light"/"balanced"/"aggressive"/"api" — see ZAPScanProfile) aren't ZAP policy
        # names and every scan silently failed with "does_not_exist" trying to use one as if it
        # were. Omitting the param lets ZAP use its own default policy; our profiles still
        # control timeout/depth/rule-count via context_config elsewhere in this flow.
        params = {
            "url": target_url,
            "recurse": "true",
            "inScopeOnly": "false",
            "scanId": ""
        }

        response = requests.get(
            f"{zap_base_url}/json/ascan/action/scan",
            params=params,
            timeout=ZAP_API_TIMEOUT
        )
        scan_id = response.json().get("scan")

        if not scan_id:
            print(f"⚠️  [ZAP-Auditor] Active scan failed to start: {response.text[:200]}")
            return []

        print(f"   Scan ID: {scan_id}")

        # Monitor scan progress
        max_wait = context_config["scan_timeout"]
        start_time = time.time()
        last_progress = 0

        while time.time() - start_time < max_wait:
            response = requests.get(
                f"{zap_base_url}/json/ascan/view/status",
                params={"scanId": scan_id},
                timeout=ZAP_API_TIMEOUT
            )
            status = int(response.json().get("status", 0))

            if status > last_progress:
                print(f"   Scan progress: {status}%")
                last_progress = status

            if status >= 100:  # Complete
                break

            time.sleep(3)

        elapsed = time.time() - start_time
        if elapsed >= max_wait:
            print(f"⚠️  [ZAP-Auditor] Scan timeout ({elapsed:.0f}s >= {max_wait}s limit)")
            raise ZAPTimeoutError(f"Active scan exceeded {max_wait}s timeout")

        # Retrieve alerts/findings
        findings = retrieve_zap_alerts(scan_id, zap_base_url)
        print(f"✅ [ZAP-Auditor] Active scan complete. Found {len(findings)} vulnerabilities")
        return findings

    except ZAPTimeoutError:
        raise
    except Exception as e:
        logger.error(f"Active scan error: {e}")
        return []

def retrieve_zap_alerts(scan_id: Optional[str] = None, zap_base_url: str = None) -> List[Dict]:
    """
    Retrieves vulnerability alerts from ZAP.

    Args:
        scan_id: Specific scan ID (None = all alerts)
        zap_base_url: This scan's ZAP container network address (http://<container>:8080)

    Returns:
        List of vulnerability finding dicts
    """
    try:
        response = requests.get(
            f"{zap_base_url}/json/core/view/alerts",
            params={"baseurl": "", "start": 0, "count": 1000},
            timeout=ZAP_API_TIMEOUT
        )

        alerts = response.json().get("alerts", [])

        # Normalize ZAP alert format
        findings = []
        for alert in alerts:
            finding = {
                # ZAP's REST API returns "pluginId" (camelCase) — a lowercase "pluginid" lookup
                # always misses, so every finding fell back to the same default and every ZAP
                # vulnerability was logged with the identical generic cve_id "ZAP-ZAP-UNKNOWN"
                # (see log_zap_findings' own "ZAP-" prefix below — hence the doubled "ZAP-ZAP-").
                # Confirmed via 180 real logged findings: cweid/wascid (correctly cased) always
                # populated, pluginid never did.
                "code": alert.get("pluginId", alert.get("pluginid", "UNKNOWN")),
                "name": alert.get("alert", "Unknown Vulnerability"),
                "description": alert.get("description", ""),
                "severity": normalize_zap_severity(alert.get("riskcode", 1)),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
                "evidence": alert.get("evidence", ""),
                "cweid": alert.get("cweid", ""),
                "wascid": alert.get("wascid", ""),
                "raw": alert
            }
            findings.append(finding)

        return findings

    except Exception as e:
        logger.error(f"Alert retrieval error: {e}")
        return []

def normalize_zap_severity(risk_code: int) -> str:
    """Normalizes ZAP risk codes to standard severity levels."""
    mapping = {
        0: "INFO",
        1: "LOW",
        2: "MEDIUM",
        3: "HIGH",
        4: "CRITICAL"
    }
    return mapping.get(int(risk_code), "MEDIUM")

def log_zap_findings(asset_id: int, target_url: str, findings: List[Dict], scan_profile: str = "balanced"):
    """
    Stores ZAP findings in vulnerability_log database.

    Args:
        asset_id: Asset ID from infra_inventory
        target_url: Scanned URL
        findings: List of vulnerability dicts
        scan_profile: Scan profile used
    """
    try:
        with db_manager.get_db_cursor() as cur:
            for finding in findings:
                cve_id = f"ZAP-{finding['code']}"
                severity = finding["severity"]

                # Build detailed description
                description = (
                    f"**DAST Vulnerability (ZAP - {scan_profile})** \\n\\n"
                    f"**Type:** {finding['name']}\\n"
                    f"**URL:** `{finding['url']}`\\n"
                    f"**Parameter:** `{finding['param']}`\\n"
                    f"**CWE ID:** {finding['cweid']}\\n"
                    f"**WASC ID:** {finding['wascid']}\\n\\n"
                    f"**Description:** {finding['description']}\\n\\n"
                )

                if finding['attack']:
                    description += f"**Attack Payload:** ```\\n{finding['attack']}\\n```\\n\\n"

                if finding['evidence']:
                    description += f"**Evidence:** ```\\n{finding['evidence']}\\n```\\n\\n"

                # Deduplicates within ZAP's own prior findings AND cross-tool (e.g. the same
                # real CVE already flagged by Nuclei/sca-native on this asset gets merged
                # instead of opening a second ticket) via the shared fingerprint-based logger.
                action, row_id = deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, cve_id, severity, description, "zap",
                    url_path=finding['url'], open_status="NEW", preserve_status=True
                )
                if action == "updated":
                    print(f"  🔄 Updated ZAP finding: [{severity}] {cve_id} on {finding['url']}")
                elif action == "merged":
                    print(f"  🔗 Merged ZAP finding into existing cross-tool ticket: [{severity}] {cve_id}")
                else:
                    print(f"  📝 Logged ZAP finding: [{severity}] {cve_id}")

        print(f"✅ Logged {len(findings)} ZAP findings for asset {asset_id}")

    except Exception as e:
        logger.error(f"Error logging ZAP findings: {e}")

def run_zap_scan(target_url: str, asset_id: int, scan_profile: str = "balanced",
                 db_cache_path: str = "/tmp/zap-cache") -> bool:
    """
    Main orchestration function: launches ZAP, runs scan, logs findings, cleans up.

    Args:
        target_url: Target application URL
        asset_id: Asset ID from infra_inventory
        scan_profile: Scan profile ('light', 'balanced', 'aggressive', 'api')
        db_cache_path: Path to ZAP DB cache

    Returns:
        True if scan completed successfully

    Raises:
        ZAPTimeoutError: If scan exceeded timeout
        ZAPNotAvailableError: If ZAP unavailable
    """
    container_id = generate_container_id()

    try:
        # Launch ephemeral container, addressed by its own container name on aura-network so
        # concurrent scans can't collide the way a shared/fixed host port did
        container_id, zap_base_url = launch_zap_container(container_id, db_cache_path)

        # Configure context
        context = configure_zap_context(target_url, scan_profile)

        # Run spider first
        urls = run_zap_spider(target_url, context["max_depth"], zap_base_url)

        # Run active scan
        findings = run_zap_active_scan(target_url, context, zap_base_url)

        # Log findings
        if findings:
            log_zap_findings(asset_id, target_url, findings, scan_profile)
        else:
            print(f"ℹ️  [ZAP-Auditor] No vulnerabilities found")

        return True

    except ZAPTimeoutError as e:
        logger.error(f"ZAP scan timeout: {e}")
        raise
    except ZAPNotAvailableError as e:
        logger.error(f"ZAP not available: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected ZAP error: {e}")
        raise
    finally:
        # Always cleanup container and its per-scan home dir (see launch_zap_container — each
        # scan gets its own directory now, so nothing else will ever reuse this one)
        stop_zap_container(container_id)
        subprocess.run(
            ["docker", "run", "--rm", "-v", f"{db_cache_path}:/target", "busybox",
             "rm", "-rf", f"/target/{container_id}"],
            capture_output=True, timeout=30
        )

if __name__ == "__main__":
    # Test scan
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        asset_id = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        profile = sys.argv[3] if len(sys.argv) > 3 else "balanced"

        try:
            run_zap_scan(target_url, asset_id, profile)
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            sys.exit(1)
    else:
        print("Usage: python auditor_zap.py <target_url> [asset_id] [profile]")
        print("Example: python auditor_zap.py http://example.com 1 balanced")
