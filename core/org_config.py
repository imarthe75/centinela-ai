"""
Organisation-specific names (Vault namespace, container names, SSH key, identity-provider URLs), read from the environment.

Nothing in the code base hard-codes a company, host or domain: every deployment sets these in its private `.env`.
Defaults are neutral so a fresh install works with its own names.
"""
import os

VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE", "centinela").strip("/")
WAZUH_MANAGER_CONTAINER = os.getenv("WAZUH_MANAGER_CONTAINER", "wazuh-manager")
SSH_DEFAULT_KEY = os.getenv("SSH_DEFAULT_KEY", "/app/keys/default.key")
AUTHENTIK_URL = os.getenv("AUTHENTIK_URL", "https://auth.example.internal")
AUTHENTIK_SERVER_CONTAINER = os.getenv("AUTHENTIK_SERVER_CONTAINER", "authentik-server")
AUTHENTIK_SSH_TARGET = os.getenv("AUTHENTIK_SSH_TARGET", "")          # user@host used to reach the identity provider's shell
AUTHENTIK_SSH_KEY = os.getenv("AUTHENTIK_SSH_KEY", "keys/default.key")
PUBLIC_BASE_URL = os.getenv("CENTINELA_PUBLIC_URL", "https://centinela.example.internal")
REPORT_ORG_NAME = os.getenv("REPORT_ORG_NAME", "Centinela-AI")
CORE_COMPOSE_PATH = os.getenv("CORE_COMPOSE_PATH", "/app/core/docker-compose.yml")
CORE_CONTAINER_PREFIX = os.getenv("CORE_CONTAINER_PREFIX", "core-")


def vault_path(*parts: str) -> str:
    """`<namespace>/ansible/<asset>` style KV path (no mount point, no leading slash)."""
    return "/".join([VAULT_NAMESPACE] + [p.strip("/") for p in parts])
