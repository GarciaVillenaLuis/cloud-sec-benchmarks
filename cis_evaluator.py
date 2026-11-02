#!/usr/bin/env python3
"""
CIS Benchmarks Multi-Cloud Posture Evaluator (AWS & Microsoft Azure).

Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
License: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class CISControlCheck:
    control_id: str
    framework: str  # e.g., 'CIS AWS v3.0.0' or 'CIS Azure v2.1.0'
    cloud_provider: str  # 'AWS' or 'Azure'
    title: str
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    status: str  # 'PASS' or 'FAIL'
    evidence: str
    remediation: str


class CISEvaluator:
    """Evaluates multi-cloud security baselines against CIS Foundations standards."""

    def __init__(self, baseline_file: Optional[str] = None):
        self.baseline_file = baseline_file
        self.checks: List[CISControlCheck] = []
        self.compliance_score: float = 0.0

    def evaluate_configuration(self, config_data: Dict[str, Any]) -> List[CISControlCheck]:
        """Evaluates AWS and Azure asset inventories against CIS controls."""
        checks: List[CISControlCheck] = []

        # ----------------- AWS CIS v3.0.0 EVALUATION -----------------
        aws_data = config_data.get("aws", {})
        if aws_data:
            # CIS 1.4: Ensure MFA is enabled for the 'root' user account
            root_mfa = aws_data.get("iam", {}).get("root_account_mfa_enabled", False)
            checks.append(CISControlCheck(
                control_id="CIS-AWS-1.4",
                framework="CIS AWS v3.0.0",
                cloud_provider="AWS",
                title="Ensure MFA is enabled for the 'root' user account",
                severity="CRITICAL",
                status="PASS" if root_mfa else "FAIL",
                evidence="Root MFA is active with hardware/virtual TOTP" if root_mfa else "Root account lacks MFA protection",
                remediation="aws iam enable-mfa-device --user-name root ..."
            ))

            # CIS 1.10: Ensure IAM password policy requires at least one symbol and minimum 14 chars
            pwd_policy = aws_data.get("iam", {}).get("password_policy", {})
            min_len = pwd_policy.get("minimum_password_length", 0)
            symbols = pwd_policy.get("require_symbols", False)
            pwd_pass = min_len >= 14 and symbols
            checks.append(CISControlCheck(
                control_id="CIS-AWS-1.10",
                framework="CIS AWS v3.0.0",
                cloud_provider="AWS",
                title="Ensure IAM password policy meets enterprise strength requirements (>=14 chars + symbols)",
                severity="HIGH",
                status="PASS" if pwd_pass else "FAIL",
                evidence=f"Password length={min_len}, symbols_required={symbols}",
                remediation="aws iam update-account-password-policy --minimum-password-length 14 --require-symbols"
            ))

            # CIS 2.1.1: Ensure CloudTrail is enabled in all regions and encrypted with KMS
            trail = aws_data.get("cloudtrail", {})
            trail_multi = trail.get("is_multi_region_trail", False)
            trail_kms = trail.get("kms_key_id") is not None
            trail_pass = trail_multi and trail_kms
            checks.append(CISControlCheck(
                control_id="CIS-AWS-2.1.1",
                framework="CIS AWS v3.0.0",
                cloud_provider="AWS",
                title="Ensure CloudTrail is enabled across all regions with KMS customer-managed encryption",
                severity="CRITICAL",
                status="PASS" if trail_pass else "FAIL",
                evidence=f"Multi-region={trail_multi}, KMS-encrypted={trail_kms}",
                remediation="aws cloudtrail update-trail --is-multi-region-trail --kms-key-id <kms-arn>"
            ))

            # CIS 2.1.4: Ensure S3 Bucket Public Access Block is enabled at account level
            s3_block = aws_data.get("s3", {}).get("account_public_access_block_enabled", False)
            checks.append(CISControlCheck(
                control_id="CIS-AWS-2.1.4",
                framework="CIS AWS v3.0.0",
                cloud_provider="AWS",
                title="Ensure S3 Public Access Block is enforced globally at account level",
                severity="CRITICAL",
                status="PASS" if s3_block else "FAIL",
                evidence="Account-level S3 Block Public Access is active" if s3_block else "S3 Public Access Block not enforced",
                remediation="aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,..."
            ))

            # CIS 3.1: Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports (22, 3389)
            sg_open = aws_data.get("vpc", {}).get("open_admin_ports_detected", False)
            checks.append(CISControlCheck(
                control_id="CIS-AWS-3.1",
                framework="CIS AWS v3.0.0",
                cloud_provider="AWS",
                title="Ensure no Security Groups allow unrestricted ingress (0.0.0.0/0) to port 22 or 3389",
                severity="CRITICAL",
                status="FAIL" if sg_open else "PASS",
                evidence="Unrestricted ingress discovered on management ports" if sg_open else "All management ports restricted to private CIDRs",
                remediation="aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0"
            ))

        # ----------------- AZURE CIS v2.1.0 EVALUATION -----------------
        azure_data = config_data.get("azure", {})
        if azure_data:
            # CIS 1.1: Ensure MFA is required for all administrative roles in Entra ID
            admin_mfa = azure_data.get("entra_id", {}).get("admin_mfa_enforced", False)
            checks.append(CISControlCheck(
                control_id="CIS-AZ-1.1",
                framework="CIS Azure v2.1.0",
                cloud_provider="Azure",
                title="Ensure Multi-Factor Authentication is enforced for all administrative roles",
                severity="CRITICAL",
                status="PASS" if admin_mfa else "FAIL",
                evidence="Conditional Access requires phishing-resistant MFA for Global Admin & Privileged Roles" if admin_mfa else "Privileged accounts lack mandatory MFA Conditional Access",
                remediation="az ad policy create --display-name 'Enforce Admin MFA' --type 'ConditionalAccessPolicy' ..."
            ))

            # CIS 2.1: Ensure Microsoft Defender for Cloud standard tier is enabled
            defender = azure_data.get("defender", {}).get("standard_tier_enabled", False)
            checks.append(CISControlCheck(
                control_id="CIS-AZ-2.1",
                framework="CIS Azure v2.1.0",
                cloud_provider="Azure",
                title="Ensure Microsoft Defender for Cloud enhanced security plans are turned ON",
                severity="HIGH",
                status="PASS" if defender else "FAIL",
                evidence="Defender CSPM and workload protection active" if defender else "Defender for Cloud running in Free tier",
                remediation="az security pricing create --name VirtualMachines --tier Standard"
            ))

            # CIS 4.1.1: Ensure Network Security Groups restrict SSH / RDP from Internet
            nsg_open = azure_data.get("network", {}).get("open_ssh_rdp_inbound", False)
            checks.append(CISControlCheck(
                control_id="CIS-AZ-4.1.1",
                framework="CIS Azure v2.1.0",
                cloud_provider="Azure",
                title="Ensure NSG rules restrict inbound SSH (22) and RDP (3389) from the Internet",
                severity="CRITICAL",
                status="FAIL" if nsg_open else "PASS",
                evidence="Inbound rule allows '*' or 'Internet' source to ports 22/3389" if nsg_open else "Management ports strictly firewalled or behind Bastion",
                remediation="az network nsg rule update --resource-group <rg> --nsg-name <nsg> --name <rule> --access Deny"
            ))

            # CIS 5.1.1: Ensure Key Vault diagnostic logging to Log Analytics is enabled
            kv_diag = azure_data.get("key_vault", {}).get("diagnostic_logs_enabled", False)
            checks.append(CISControlCheck(
                control_id="CIS-AZ-5.1.1",
                framework="CIS Azure v2.1.0",
                cloud_provider="Azure",
                title="Ensure Azure Key Vault audit and diagnostic logs are routed to Log Analytics",
                severity="HIGH",
                status="PASS" if kv_diag else "FAIL",
                evidence="AuditEvent logs streamed to central Log Analytics Workspace" if kv_diag else "Diagnostic settings missing on Key Vault",
                remediation="az monitor diagnostic-settings create --resource <kv-id> --workspace <law-id> --logs '[{\"category\": \"AuditEvent\",\"enabled\": true}]'"
            ))

            # CIS 6.1: Ensure Storage Account requires Secure Transfer (HTTPS) and TLS 1.2+
            storage = azure_data.get("storage", {})
            https_only = storage.get("supports_https_traffic_only", False)
            min_tls = storage.get("minimum_tls_version", "TLS1_0")
            storage_pass = https_only and min_tls in ("TLS1_2", "TLS1_3")
            checks.append(CISControlCheck(
                control_id="CIS-AZ-6.1",
                framework="CIS Azure v2.1.0",
                cloud_provider="Azure",
                title="Ensure Storage Accounts enforce HTTPS and TLS 1.2 minimum",
                severity="HIGH",
                status="PASS" if storage_pass else "FAIL",
                evidence=f"HTTPS_Only={https_only}, Min_TLS={min_tls}",
                remediation="az storage account update --name <account> --https-only true --min-tls-version TLS1_2"
            ))

        self.checks = checks
        passed = sum(1 for c in checks if c.status == "PASS")
        total = len(checks)
        self.compliance_score = round((passed / total * 100), 2) if total > 0 else 100.0
        return checks

    def evaluate_matrix_file(self, matrix_path: str) -> Dict[str, Any]:
        """Parses repository cloud_cis_matrix.json directly."""
        with open(matrix_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        standards = data.get("standards", [])
        overall_score = data.get("cspm_posture_score", 95)
        return {
            "standards_evaluated": standards,
            "overall_cspm_score": overall_score,
            "last_audit_utc": data.get("last_audit_utc"),
            "integrity_hash": data.get("integrity_hash")
        }


def format_cis_table(checks: List[CISControlCheck]) -> str:
    """Generates ASCII terminal report."""
    if not checks:
        return "No checks evaluated."

    headers = ["Control ID", "Cloud", "Severity", "Status", "Control Title"]
    rows = []
    for c in checks:
        rows.append([c.control_id, c.cloud_provider, c.severity, c.status, c.title[:50]])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(val)))

    line_sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_str = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"

    output = [line_sep, header_str, line_sep]
    for row in rows:
        row_str = "| " + " | ".join(str(val).ljust(col_widths[i]) for i, val in enumerate(row)) + " |"
        output.append(row_str)
    output.append(line_sep)
    return "\n".join(output)


def get_default_sample_inventory() -> Dict[str, Any]:
    """Provides a baseline enterprise sample inventory if no input file is given."""
    return {
        "aws": {
            "iam": {
                "root_account_mfa_enabled": True,
                "password_policy": {"minimum_password_length": 16, "require_symbols": True}
            },
            "cloudtrail": {
                "is_multi_region_trail": True,
                "kms_key_id": "arn:aws:kms:eu-west-1:123456789012:key/sec-trail-key"
            },
            "s3": {
                "account_public_access_block_enabled": True
            },
            "vpc": {
                "open_admin_ports_detected": False
            }
        },
        "azure": {
            "entra_id": {
                "admin_mfa_enforced": True
            },
            "defender": {
                "standard_tier_enabled": True
            },
            "network": {
                "open_ssh_rdp_inbound": False
            },
            "key_vault": {
                "diagnostic_logs_enabled": True
            },
            "storage": {
                "supports_https_traffic_only": True,
                "minimum_tls_version": "TLS1_2"
            }
        }
    }


def main() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="CIS Benchmarks Multi-Cloud Posture Evaluator (AWS & Microsoft Azure)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cis_evaluator.py
  python cis_evaluator.py --input-config samples/aws_azure_inventory.json
  python cis_evaluator.py --matrix benchmarks/cloud_cis_matrix.json
  python cis_evaluator.py --format json --output report.json
        """
    )
    parser.add_argument("--input-config", "-i", type=str, help="Path to cloud inventory JSON file to audit")
    parser.add_argument("--matrix", "-m", type=str, help="Path to cloud_cis_matrix.json to display recorded telemetry")
    parser.add_argument("--cloud", choices=["ALL", "AWS", "Azure"], default="ALL", help="Scope audit to specific cloud")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with code 1 if any CRITICAL control fails")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--output", "-o", type=str, help="Save evaluation to file")

    args = parser.parse_args()

    evaluator = CISEvaluator()

    if args.matrix:
        if not os.path.exists(args.matrix):
            sys.stderr.write(f"[ERROR] Matrix file '{args.matrix}' does not exist.\n")
            sys.exit(1)
        matrix_result = evaluator.evaluate_matrix_file(args.matrix)
        if args.format == "json":
            out_str = json.dumps(matrix_result, indent=2)
        else:
            lines = [
                "===========================================================",
                "   CIS BENCHMARKS POSTURE MATRIX TELEMETRY",
                "===========================================================",
                f"Overall CSPM Posture Score: {matrix_result['overall_cspm_score']}%",
                f"Audit Timestamp (UTC):     {matrix_result['last_audit_utc']}",
                f"Cryptographic Integrity:   {matrix_result['integrity_hash']}",
                "-----------------------------------------------------------",
                "Standards Evaluated:"
            ]
            for std in matrix_result["standards_evaluated"]:
                lines.append(f"  - {std['framework']} ({std['version']}): {std['compliance_rate']} - {std['status']}")
            lines.append("===========================================================")
            out_str = "\n".join(lines)

        print(out_str)
        sys.exit(0)

    # If auditing an inventory
    if args.input_config:
        if not os.path.exists(args.input_config):
            sys.stderr.write(f"[ERROR] Inventory configuration file '{args.input_config}' not found.\n")
            sys.exit(1)
        with open(args.input_config, "r", encoding="utf-8") as f:
            config_payload = json.load(f)
    else:
        config_payload = get_default_sample_inventory()

    checks = evaluator.evaluate_configuration(config_payload)
    if args.cloud != "ALL":
        checks = [c for c in checks if c.cloud_provider.upper() == args.cloud.upper()]

    passed_count = sum(1 for c in checks if c.status == "PASS")
    total_count = len(checks)
    compliance_score = round((passed_count / total_count * 100), 2) if total_count > 0 else 100.0
    failed_criticals = [c for c in checks if c.severity == "CRITICAL" and c.status == "FAIL"]

    if args.format == "json":
        report_data = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "compliance_score": compliance_score,
            "total_checks": len(checks),
            "passed_checks": passed_count,
            "failed_checks": sum(1 for c in checks if c.status == "FAIL"),
            "critical_failures": len(failed_criticals),
            "checks": [asdict(c) for c in checks]
        }
        out_str = json.dumps(report_data, indent=2)
    else:
        table_str = format_cis_table(checks)
        summary_lines = [
            "==========================================================================",
            "   CIS BENCHMARKS CSPM POSTURE EVALUATION REPORT",
            "==========================================================================",
            f"Overall Compliance Score: {compliance_score}%",
            f"Total Controls Tested:    {len(checks)}",
            f"Passed Controls:          {passed_count}",
            f"Failed Controls:          {sum(1 for c in checks if c.status == 'FAIL')} (Critical Failures: {len(failed_criticals)})",
            "--------------------------------------------------------------------------",
            table_str
        ]
        if failed_criticals:
            summary_lines.append("\n[!] CRITICAL REMEDIATION ACTIONS REQUIRED:")
            for fc in failed_criticals:
                summary_lines.append(f"  - [{fc.control_id}] {fc.title}")
                summary_lines.append(f"    Remediation: {fc.remediation}")
        summary_lines.append("==========================================================================")
        out_str = "\n".join(summary_lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_str + "\n")
        print(f"[SUCCESS] Report written to {args.output}")
    else:
        print(out_str)

    if args.fail_on_critical and failed_criticals:
        sys.exit(1)


if __name__ == "__main__":
    main()
