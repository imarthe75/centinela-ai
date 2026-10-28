"""Every developer-facing rule id the auditors emit must appear in the developer-standards skill, so the skill cannot drift from the code.
Ids that are not something a developer can avoid by writing different code (CVE numbers, runtime detections, internal markers) are exempt by prefix."""
import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PAT = re.compile(r'["\']([A-Z][A-Z0-9]+(?:-[A-Z0-9]+){1,})["\']')
# Only what a developer cannot influence by writing different code: CVE numbers, runtime detections (identity, kernel, threat intel),
# OSINT and internal markers. Everything else must be in the skill by its full id.
_EXEMPT = ("CVE-", "SCA-CVE-", "HTTP-", "UTF-", "SHA-", "CVSS-", "SELF-", "ITDR-", "EBPF-", "HEURISTIC-", "OSINT-", "BLOODHOUND-", "CTI-", "HOST-",
           "GITLAB-REPO", "BRUTE-", "BAJO-", "PRIVATE-", "ART-", "NMAP-", "SCAN-", "A0", "A1")


class TestSkillRuleCoverage(unittest.TestCase):
    def test_skill_mentions_every_developer_facing_rule(self):
        skill = open(os.path.join(ROOT, "skills/centinela-developer-standards/SKILL.md"), encoding="utf-8").read()
        emitted = set()
        for f in glob.glob(os.path.join(ROOT, "auditors/auditor_*.py")):
            emitted.update(m.group(1) for m in _PAT.finditer(open(f, encoding="utf-8").read()))
        missing = sorted(i for i in emitted if len(i) > 8 and not i.startswith(_EXEMPT) and i not in skill)
        self.assertEqual(missing, [], "rules not documented in the skill:\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main()
