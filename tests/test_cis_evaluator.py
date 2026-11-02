#!/usr/bin/env python3
"""
Unit tests for CIS Multi-Cloud Posture Evaluator.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from cis_evaluator import CISEvaluator, format_cis_table, get_default_sample_inventory


class TestCISEvaluator(unittest.TestCase):
    def setUp(self):
        self.evaluator = CISEvaluator()
        self.sample_inv = get_default_sample_inventory()

    def test_default_inventory_is_compliant(self):
        checks = self.evaluator.evaluate_configuration(self.sample_inv)
        self.assertEqual(len(checks), 10)
        self.assertEqual(self.evaluator.compliance_score, 100.0)
        for check in checks:
            self.assertEqual(check.status, "PASS")

    def test_detect_aws_root_mfa_missing(self):
        inv = json.loads(json.dumps(self.sample_inv))
        inv["aws"]["iam"]["root_account_mfa_enabled"] = False
        checks = self.evaluator.evaluate_configuration(inv)
        root_check = next(c for c in checks if c.control_id == "CIS-AWS-1.4")
        self.assertEqual(root_check.status, "FAIL")
        self.assertEqual(root_check.severity, "CRITICAL")
        self.assertLess(self.evaluator.compliance_score, 100.0)

    def test_detect_azure_open_management_ports(self):
        inv = json.loads(json.dumps(self.sample_inv))
        inv["azure"]["network"]["open_ssh_rdp_inbound"] = True
        checks = self.evaluator.evaluate_configuration(inv)
        nsg_check = next(c for c in checks if c.control_id == "CIS-AZ-4.1.1")
        self.assertEqual(nsg_check.status, "FAIL")
        self.assertEqual(nsg_check.severity, "CRITICAL")

    def test_detect_aws_s3_public_access_block_disabled(self):
        inv = json.loads(json.dumps(self.sample_inv))
        inv["aws"]["s3"]["account_public_access_block_enabled"] = False
        checks = self.evaluator.evaluate_configuration(inv)
        s3_check = next(c for c in checks if c.control_id == "CIS-AWS-2.1.4")
        self.assertEqual(s3_check.status, "FAIL")

    def test_table_formatter(self):
        checks = self.evaluator.evaluate_configuration(self.sample_inv)
        out = format_cis_table(checks)
        self.assertIn("CIS-AWS-1.4", out)
        self.assertIn("CIS-AZ-1.1", out)
        self.assertIn("PASS", out)


if __name__ == "__main__":
    unittest.main()
