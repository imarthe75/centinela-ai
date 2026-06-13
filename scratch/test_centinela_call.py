import sys
import os
sys.path.insert(0, '/app')

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

# We want to patch centinela.py's correlate_vulnerability to print intermediate values.
# Instead of modifying the file directly, let's just write a test script that reproduces the function's logic.

import centinela
# Let's inspect the environment provider order
print("Active Provider Order:", centinela.providers_order)
print("Active Provider:", getattr(centinela, 'active_provider', None))

# Let's run it and intercept the prints
res = correlate_vulnerability(vuln)
print("Returned Result:")
print(res)
