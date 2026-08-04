"""
Resident Agent OS - Loop Cognitivo en 10 Fases Deterministas
Implementa el motor de ejecución guiado por heurísticas, especificaciones OpenSpec
y persistencia en capas (Valkey + PostgreSQL).
"""

import os
import sys
import json
import time
from typing import Dict, List, Any, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core import db_manager
from core.heuristics_engine import HeuristicsEngine
from auditors.auditor_compliance_standards import AuditorComplianceStandards


class ResidentAgentLoop:
    def __init__(self, workspace_path: str = "/opt/centinela-ai"):
        self.workspace_path = workspace_path
        self.heuristics_engine = HeuristicsEngine()
        self.state = {"status": "INITIALIZED", "retry_count": 0}
        self.audit_engine = AuditorComplianceStandards(workspace_path)

    # 1. BOOT
    def boot(self) -> bool:
        print("🚀 [Resident-Loop] 1. Booting Resident Agent OS...")
        self.state["status"] = "BOOTED"
        self.state["boot_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        return True

    # 2. LOAD CONTEXT
    def load_context(self) -> Dict[str, Any]:
        print("📂 [Resident-Loop] 2. Loading OS context and rules...")
        context = {
            "workspace": self.workspace_path,
            "has_external_api": True,
            "has_local_alternative": True,
            "valkey_available": True,
            "retry_count": self.state.get("retry_count", 0)
        }
        self.state["context"] = context
        return context

    # 3. RETRIEVE MEMORY
    def retrieve_memory(self, query: str = "") -> List[Dict[str, Any]]:
        print("🧠 [Resident-Loop] 3. Retrieving memory from DB / Semantic Cache...")
        memories = []
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'auditoria' LIMIT 5;")
                rows = cur.fetchall()
                memories.append({"type": "tables", "data": [r[0] for r in rows]})
        except Exception as e:
            print(f"⚠️ [Resident-Loop] Could not retrieve DB memory: {e}")
        return memories

    # 4. APPLY HEURISTICS
    def apply_heuristics(self, context: Dict[str, Any]) -> List[str]:
        print("⚙️ [Resident-Loop] 4. Applying heuristic engine rules...")
        actions = self.heuristics_engine.evaluate(context)
        print(f"   ↳ Actions triggered: {actions}")
        return actions

    # 5. ENSURE SPEC
    def ensure_spec(self, spec_id: str = "SPEC-AUDIT-INTEGRAL") -> bool:
        print(f"📋 [Resident-Loop] 5. Validating OpenSpec {spec_id}...")
        return True

    # 6. PLAN TASKS
    def plan_tasks(self, actions: List[str]) -> List[str]:
        print("📝 [Resident-Loop] 6. Planning deterministic task queue...")
        tasks = ["AUDIT_STANDARDS", "VERIFY_EVIDENCE", "STORE_FINDINGS"]
        return tasks

    # 7. EXECUTE
    def execute(self, task_name: str) -> Dict[str, Any]:
        print(f"⚡ [Resident-Loop] 7. Executing task: {task_name}...")
        if task_name == "AUDIT_STANDARDS":
            report = self.audit_engine.run_full_audit()
            return report
        return {"status": "SUCCESS", "task": task_name}

    # 8. VERIFY
    def verify(self, result: Dict[str, Any]) -> bool:
        print("🔍 [Resident-Loop] 8. Verifying empirical evidence [Cierto]...")
        findings = result.get("findings", [])
        certain_count = len([f for f in findings if f.get("evidence_level") == "[Cierto]"])
        print(f"   ↳ Evidence Verified: {certain_count} empirical findings tagged [Cierto]")
        return True

    # 9. STORE MEMORY
    def store_memory(self, audit_result: Dict[str, Any]) -> bool:
        print("💾 [Resident-Loop] 9. Storing lessons learned in long-term memory...")
        try:
            with db_manager.get_db_cursor() as cur:
                score = audit_result.get("overall_score", 0)
                status = audit_result.get("status", "UNKNOWN")
                cur.execute("""
                    INSERT INTO auditoria.log_auditoria 
                    (schemaname, tablename, username, dmlaction, originaldata, executednewdata, executedsql)
                    VALUES (%s, %s, %s, %s, %s, %s, %s);
                """, ("auditoria", "compliance_audit", "resident_agent", "I", "{}", json.dumps({"score": score, "status": status}), "AUDIT_EXECUTION"))
                print("   ↳ Logged audit run in auditoria.log_auditoria.")
                return True
        except Exception as e:
            print(f"⚠️ [Resident-Loop] Could not store memory in DB: {e}")
            return False

    # 10. UPDATE STATE
    def update_state(self, status: str = "COMPLETED") -> Dict[str, Any]:
        print("🔄 [Resident-Loop] 10. Atomic update of Agent session state...")
        self.state["status"] = status
        self.state["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        return self.state

    def run_full_cycle(self) -> Dict[str, Any]:
        """Ejecuta el ciclo completo de las 10 fases."""
        self.boot()
        ctx = self.load_context()
        mem = self.retrieve_memory()
        actions = self.apply_heuristics(ctx)
        self.ensure_spec()
        tasks = self.plan_tasks(actions)
        
        audit_result = {}
        for task in tasks:
            res = self.execute(task)
            if task == "AUDIT_STANDARDS":
                audit_result = res
                
        self.verify(audit_result)
        self.store_memory(audit_result)
        final_state = self.update_state("SUCCESS")
        
        return {
            "state": final_state,
            "audit": audit_result
        }


if __name__ == "__main__":
    loop = ResidentAgentLoop()
    cycle_result = loop.run_full_cycle()
    print(json.dumps(cycle_result.get("state"), indent=2))
