import sys
import os
sys.path.insert(0, '/app')
from core import db_manager
from psycopg2.extras import RealDictCursor

# Inject the environment variables from .env if needed
# But since this will be run inside docker, the docker container already has them.

from centinela import correlate_vulnerability

vuln = {
    'id': 12844062,
    'cve_id': 'CVE-2026-46099',
    'severity': 'HIGH',
    'description': 'Vulnerabilidad crítica en opensign-server.',
    'asset_name': 'opensign-server',
    'asset_type': 'CONTAINER',
    'endpoint': '10.4.5.10:8080'
}

print("Running correlate_vulnerability...")
res = correlate_vulnerability(vuln)
print("Result:")
import pprint
pprint.pprint(res)
