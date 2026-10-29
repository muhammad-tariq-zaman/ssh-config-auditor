import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import parse_ssh_config, audit


class TestSshAuditor(unittest.TestCase):
    def test_global_and_host_blocks(self):
        blocks = parse_ssh_config("PasswordAuthentication yes\nHost web\n  Port 2222\n")
        self.assertEqual(blocks["*"]["passwordauthentication"], "yes")
        self.assertEqual(blocks["web"]["port"], "2222")

    def test_password_auth_flagged(self):
        findings = audit(parse_ssh_config("Host *\n  PasswordAuthentication yes\n"))
        self.assertTrue(any(f[1] == "PasswordAuthentication" for f in findings))

    def test_clean_config_no_findings(self):
        text = "Host *\n  PasswordAuthentication no\n  PubkeyAuthentication yes\n"
        self.assertEqual(audit(parse_ssh_config(text)), [])

    def test_strict_host_key_flagged(self):
        findings = audit(parse_ssh_config("StrictHostKeyChecking no\n"))
        self.assertTrue(any(f[1] == "StrictHostKeyChecking" for f in findings))


if __name__ == "__main__":
    unittest.main()
