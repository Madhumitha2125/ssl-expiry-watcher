"""
Automated tests for SSL Certificate Expiry Watcher.
Runs verification on SSL checker fallback, database CRUD, and notifier logic.
"""

import sys
import unittest
from datetime import datetime, timezone

# Add workspace root to system path to import modules
sys.path.append(".")

from ssl_checker import _parse_rdn, get_ssl_expiry
import database
import alerts_service


class TestSSLWatcher(unittest.TestCase):
    
    def test_parse_rdn(self):
        """Test parsing of certificate RDN tuples."""
        # Simple common name
        rdns = ((('commonName', 'example.com'),),)
        self.assertEqual(_parse_rdn(rdns), "example.com")
        
        # Combined commonName and organizationName
        rdns_comb = ((('organizationName', 'My Org Corp'),), (('commonName', 'test.com'),))
        self.assertEqual(_parse_rdn(rdns_comb), "test.com (My Org Corp)")
        
        # Missing values
        self.assertEqual(_parse_rdn(None), "Unknown")
        self.assertEqual(_parse_rdn(()), "Unknown")
        
    def test_get_ssl_expiry_valid_domain(self):
        """Test scanning a known valid domain (google.com)."""
        res = get_ssl_expiry("google.com")
        self.assertEqual(res["domain"], "google.com")
        self.assertTrue(res["is_valid"])
        self.assertIsNone(res["error"])
        self.assertIsNotNone(res["expiry_date"])
        self.assertIsNotNone(res["days_left"])
        self.assertIn("Google", res["issuer"])
        self.assertIn("google.com", res["subject"])
        self.assertIsNotNone(res["serial_number"])

    def test_get_ssl_expiry_expired_domain(self):
        """Test scanning a known expired domain (expired.badssl.com)."""
        res = get_ssl_expiry("expired.badssl.com")
        self.assertEqual(res["domain"], "expired.badssl.com")
        self.assertFalse(res["is_valid"])
        self.assertIsNotNone(res["error"])
        self.assertIn("expired", res["error"].lower())
        self.assertIsNotNone(res["expiry_date"])
        self.assertIsNotNone(res["days_left"])
        
        # Expired domain must have negative days left and CRITICAL status
        self.assertLess(res["days_left"], 0)
        self.assertEqual(res["status"], "CRITICAL")
        self.assertIn("badssl.com", res["issuer"])

    def test_database_crud_and_history(self):
        """Test inserting, updating, fetching history, and deleting domains in database."""
        test_domain = "dummy-test-domain.xyz"
        
        # Ensure clean state
        database.delete_domain(test_domain)
        
        dummy_res = {
            "domain": test_domain,
            "expiry_date": "2026-12-31 23:59:59 UTC",
            "days_left": 180,
            "status": "SAFE",
            "error": None,
            "issuer": "Test CA",
            "subject": "dummy-test-domain.xyz",
            "serial_number": "1234567890",
            "is_valid": True
        }
        
        # 1. Upsert
        database.upsert_result(dummy_res)
        
        # 2. Get result
        retrieved = database.get_result_by_domain(test_domain)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["domain"], test_domain)
        self.assertEqual(retrieved["days_left"], 180)
        self.assertEqual(retrieved["status"], "SAFE")
        self.assertEqual(retrieved["issuer"], "Test CA")
        self.assertEqual(retrieved["serial_number"], "1234567890")
        self.assertEqual(retrieved["is_valid"], 1)
        
        # 3. Get history (should contain 1 entry)
        history = database.get_domain_history(test_domain)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["days_left"], 180)
        
        # 4. Monitored list
        monitored = database.get_all_monitored_domains()
        self.assertIn(test_domain, monitored)
        
        # 5. Delete
        database.delete_domain(test_domain)
        retrieved_deleted = database.get_result_by_domain(test_domain)
        self.assertIsNone(retrieved_deleted)
        
        history_deleted = database.get_domain_history(test_domain)
        self.assertEqual(len(history_deleted), 0)
        
    def test_alert_digest_generator(self):
        """Test building of consolidated Slack and email digest notifications."""
        results = [
            {"domain": "safe-site.com", "days_left": 45, "status": "SAFE", "error": None},
            {"domain": "warn-site.com", "days_left": 15, "status": "WARNING", "error": None},
            {"domain": "expired-site.com", "days_left": -5, "status": "CRITICAL", "error": "Expired"},
            {"domain": "error-site.com", "days_left": None, "status": "ERROR", "error": "DNS failed"}
        ]
        
        slack_msg, email_subj, email_body = alerts_service.generate_digest_message(results)
        
        # Check alerts
        self.assertIn("warn-site.com", slack_msg)
        self.assertIn("expired-site.com", slack_msg)
        self.assertIn("error-site.com", slack_msg)
        self.assertNotIn("safe-site.com", slack_msg) # Safe site shouldn't be in alerts
        
        self.assertIn("CRITICAL/WARNING", email_subj)
        self.assertIn("Expired", email_body)
        self.assertIn("DNS failed", email_body)
        self.assertNotIn("safe-site.com", email_body)


if __name__ == "__main__":
    unittest.main()
