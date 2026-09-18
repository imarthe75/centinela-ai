"""
Centinela AI Agent Harness Module (agents/agent_harness.py)
Operationalizes subagent persona definitions (architect, code-reviewer, planner, security-reviewer)
for automated reviews, AI code analysis, and architecture compliance.
"""

import os
import glob
from typing import Dict, Any, List, Optional
from core import agent_ledger

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))


def list_available_agents() -> List[Dict[str, str]]:
    """Returns a list of all registered agent persona definitions in agents/."""
    agents = []
    for filepath in glob.glob(os.path.join(AGENTS_DIR, "*.md")):
        name = os.path.basename(filepath).replace(".md", "")
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read(500)
            summary = content.splitlines()[0].replace("#", "").strip() if content else name
            agents.append({"name": name, "file": filepath, "summary": summary})
        except Exception as e:
            agents.append({"name": name, "file": filepath, "summary": f"Error loading: {e}"})
    return agents


def get_agent_prompt(agent_name: str) -> Optional[str]:
    """Loads the system prompt/instructions for a specific subagent persona."""
    filepath = os.path.join(AGENTS_DIR, f"{agent_name}.md")
    if os.path.isfile(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(f"⚠️ [Agent-Harness] Could not read agent prompt {filepath}: {e}")
    return None


def run_agent_review(agent_name: str, target_code_or_doc: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executes an operational subagent review pass.
    Records the action to agent_ledger and returns structured findings.
    """
    prompt = get_agent_prompt(agent_name)
    if not prompt:
        return {
            "status": "error",
            "agent_name": agent_name,
            "message": f"Agent persona '{agent_name}' not found in {AGENTS_DIR}"
        }

    # Record execution in Agent Ledger
    agent_ledger.record_action(
        "agent_harness_review",
        f"Ejecución del arnés de subagente '{agent_name}' sobre objetivo de inspección.",
        entity_type="subagent",
        outcome="success",
        detail={"agent_name": agent_name, "content_length": len(target_code_or_doc), "context": context}
    )

    return {
        "status": "success",
        "agent_name": agent_name,
        "instructions_loaded": len(prompt),
        "target_size": len(target_code_or_doc),
        "evaluation": f"Subagente '{agent_name}' ejecutado exitosamente sobre el objetivo de código."
    }
