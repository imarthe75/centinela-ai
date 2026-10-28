import unittest

from auditors.auditor_master_vulnerabilities import scan_coverage_rules


def ids(path, code):
    return {f["cve_id"] for f in scan_coverage_rules(path, code)}


STOMP_BAD = """
import { Stomp } from '@stomp/stompjs';
this.stompClient.configure({
  connectHeaders: { Authorization: `Bearer ${token}` },
  debug: (str) => console.log('STOMP Debug:', str),
});
"""


class TestStompDebugLogging(unittest.TestCase):
    def test_debug_logger_with_credentials_is_high(self):
        found = [f for f in scan_coverage_rules("src/ws.service.ts", STOMP_BAD) if f["cve_id"] == "FRONTEND-STOMP-DEBUG-LOGGING"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "HIGH")

    def test_silent_debug_and_commented_logger_are_not_flagged(self):
        ok = "this.client.configure({ debug: () => {} });\n// debug: (s) => console.log(s)\n"
        self.assertNotIn("FRONTEND-STOMP-DEBUG-LOGGING", ids("src/ws.service.ts", ok))

    def test_spec_files_are_ignored(self):
        self.assertNotIn("FRONTEND-STOMP-DEBUG-LOGGING", ids("src/ws.service.spec.ts", STOMP_BAD))


class TestTokenInConsole(unittest.TestCase):
    def test_logging_token_variables_is_flagged(self):
        for line in ["console.debug('refreshToken:', refreshToken);", "console.log(this.decodeToken(token));",
                     "console.log(`header ${authToken}`);", "console.info('pwd', password)"]:
            self.assertIn("FRONTEND-TOKEN-IN-CONSOLE", ids("src/a.ts", line + "\n"), line)

    def test_messages_durations_and_urls_are_not_flagged(self):
        for line in ["console.log('validarToken');", "console.debug('refresh', environment.timeRefreshToken);",
                     "console.debug(`${this.apiUrl}/auth/refresh-token`);", "console.log(tokenCount);",
                     "// console.log(token)", "console.error('Error', err);"]:
            self.assertNotIn("FRONTEND-TOKEN-IN-CONSOLE", ids("src/a.ts", line + "\n"), line)


if __name__ == "__main__":
    unittest.main()
