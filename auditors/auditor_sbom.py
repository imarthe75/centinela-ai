"""
auditor_sbom.py -- kept as the entry point `auditor_ext` already calls; it now does ONE thing: the dependency-license inventory (syft -> auditors/auditor_licenses.py).

Grype (CVE matching over the SBOM) was REMOVED on 2026-10-12: it never produced a single row in production (its ~3 GB vulnerability database never existed in this
deployment), and the CVEs of the declared dependencies already come from `sca-native` (OSV.dev, with real CVSS scoring and import-based reachability).
"""
import os


def run(asset_id: str, asset_name: str, target: str = None):
    """Entry point called by auditor_ext. `target` must be a directory (a Docker image is covered by Trivy: scripts/scan_own_images.py)."""
    scan_target = target or asset_name
    if not os.path.isdir(scan_target):
        print(f"ℹ️ [SBOM] {scan_target} is not a directory -- license inventory skipped (images are scanned by Trivy).")
        return
    from auditors import auditor_licenses
    auditor_licenses.run_license_audit(scan_target, asset_id=asset_id, display_name=asset_name)
