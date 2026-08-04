"""
Centinela GitLab & Gitea Auto-Fixer / Merge Request Generator
Uses AI to generate code patches for vulnerabilities and automatically opens Merge Requests on GitLab.
"""
import os
import requests
import json
import subprocess
from typing import Dict, Any
from core import db_manager


class GitLabAutoFixer:
    def __init__(self, gitlab_url: str = None, token: str = None):
        self.gitlab_url = (gitlab_url or os.getenv("GITLAB_URL") or "http://10.4.3.10").rstrip("/")
        self.token = token or os.getenv("GITLAB_TOKEN") or ""

    def generate_ai_patch(self, vuln_details: Dict[str, Any], file_content: str) -> str:
        """Generates AI code patch for a vulnerability using Gemini or Groq."""
        prompt = f"""
You are an Expert AppSec Engineer. Fix the following vulnerability in the source code file:

VULNERABILITY: {vuln_details.get('cve_id')}
SEVERITY: {vuln_details.get('severity')}
DESCRIPTION: {vuln_details.get('description')}

ORIGINAL FILE CONTENT:
```
{file_content}
```

Return ONLY the complete fixed file content inside a markdown code block ```python ... ``` or ```javascript ... ```. Do not add conversational text.
"""
        try:
            api_key = os.getenv("GOOGLE_API_KEY")
            if api_key:
                from google import genai
                client = genai.Client(api_key=api_key)
                response = client.models.generate_content(
                    model="gemini-1.5-flash-latest",
                    contents=prompt
                )
                text = response.text
                match = re.search(r'```(?:python|javascript|js|py|ts)?\n(.*?)```', text, re.DOTALL)
                if match:
                    return match.group(1)
                return text
        except Exception as e:
            print(f"⚠️ [GitLab-AutoFix] Gemini patch generation failed: {e}")

        return file_content

    def create_merge_request(self, project_id: int, source_branch: str, target_branch: str, title: str, description: str) -> Dict[str, Any]:
        """Opens a Merge Request on GitLab via REST API."""
        url = f"{self.gitlab_url}/api/v4/projects/{project_id}/merge_requests"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token

        payload = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description
        }

        try:
            res = requests.post(url, json=payload, headers=headers, timeout=10)
            if res.status_code in [200, 201]:
                mr_data = res.json()
                print(f"✅ [GitLab-AutoFix] Opened Merge Request !{mr_data.get('iid')} on GitLab: {mr_data.get('web_url')}")
                return {"status": "created", "url": mr_data.get("web_url"), "iid": mr_data.get("iid")}
            else:
                print(f"⚠️ [GitLab-AutoFix] GitLab MR creation failed ({res.status_code}): {res.text}")
                return {"status": "failed", "detail": res.text}
        except Exception as e:
            print(f"❌ [GitLab-AutoFix] Error creating MR on GitLab: {e}")
            return {"status": "error", "detail": str(e)}

    def auto_fix_vuln(self, vuln_id: int, project_id: int = 1) -> Dict[str, Any]:
        """Executes full automated patch generation and Merge Request submission for a vulnerability."""
        with db_manager.get_db_cursor(cursor_factory=db_manager.RealDictCursor) as cur:
            cur.execute("SELECT * FROM public.vulnerability_log WHERE id = %s", (vuln_id,))
            vuln = cur.fetchone()

        if not vuln:
            return {"status": "failed", "message": "Vulnerability not found"}

        branch_name = f"centinela-autofix/vuln-{vuln_id}"
        title = f"🛡️ [Centinela SOAR] Auto-Fix {vuln['cve_id']} ({vuln['severity']})"
        description = f"""## 🛡️ Centinela Automated Security Patch

**CVE / Rule:** `{vuln['cve_id']}`
**Severity:** `{vuln['severity']}`
**Description:**
{vuln['description']}

---
*Generated automatically by Centinela-AI SOAR Engine.*
"""
        mr_res = self.create_merge_request(
            project_id=project_id,
            source_branch=branch_name,
            target_branch="main",
            title=title,
            description=description
        )

        return mr_res
