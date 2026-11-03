# Cloud Security Benchmarks ☁️

[![CI/CD Pipeline](https://github.com/GarciaVillenaLuis/cloud-sec-benchmarks/actions/workflows/ci.yml/badge.svg)](https://github.com/GarciaVillenaLuis/cloud-sec-benchmarks/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GarciaVillenaLuis/cloud-sec-benchmarks/actions/workflows/codeql.yml/badge.svg)](https://github.com/GarciaVillenaLuis/cloud-sec-benchmarks/actions/workflows/codeql.yml)
[![CSPM Compliance](https://img.shields.io/badge/CSPM%20Compliance-98.2%25%20PASS-brightgreen?style=flat-square&logo=amazonwebservices&logoColor=white)](https://github.com/GarciaVillenaLuis/cloud-sec-benchmarks)
[![Standards](https://img.shields.io/badge/Benchmark-CIS%20AWS%20v3.0%20%7C%20Azure%20v2.1-blue?style=flat-square&logo=microsoftazure&logoColor=white)](https://www.cisecurity.org/cis-benchmarks)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)
[![Security Baseline](https://img.shields.io/badge/Architecture-Enterprise%20Multi--Cloud-orange?style=flat-square)](https://ismsforum.es/)

Automated compliance baseline checks and **CIS Benchmarks** (Center for Internet Security) posture validation rules for **AWS** and **Microsoft Azure** architectures.

Engineered and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🌟 Supported Standards & Controls

### 1. CIS Amazon Web Services Foundations Benchmark v3.0.0
- **CIS 1.4**: Mandatory hardware/virtual MFA on root account.
- **CIS 1.10**: Enterprise IAM password complexity ($\ge 14$ characters, uppercase, symbols).
- **CIS 2.1.1**: Multi-region CloudTrail enabled with Customer Managed Key (CMK) KMS encryption.
- **CIS 2.1.4**: Account-level S3 Block Public Access enforcement.
- **CIS 3.1**: Disallow unrestricted ingress (`0.0.0.0/0`) on administrative ports (SSH 22, RDP 3389).

### 2. CIS Microsoft Azure Foundations Benchmark v2.1.0
- **CIS 1.1**: Conditional Access policy enforcing phishing-resistant MFA for all administrator roles.
- **CIS 2.1**: Microsoft Defender for Cloud Standard Tier enabled across server and storage workloads.
- **CIS 4.1.1**: Network Security Groups (NSGs) restricting inbound SSH/RDP from public Internet.
- **CIS 5.1.1**: Azure Key Vault diagnostic logging routed directly to Log Analytics.
- **CIS 6.1**: Storage Accounts enforcing Secure Transfer (`HTTPS`) and minimum TLS version 1.2+.

---

## 🚀 Quick Start & CLI Usage

### Requirements
- Python 3.9+ (Zero external dependencies)

### Available Flags & Parameters

```bash
python cis_evaluator.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--input-config FILE` | `string` | Audit external cloud asset inventory JSON |
| `--matrix FILE` | `string` | Inspect repository CSPM posture matrix (`benchmarks/cloud_cis_matrix.json`) |
| `--cloud CLOUD` | `choice` | Filter audit scope: `ALL`, `AWS`, or `Azure` |
| `--fail-on-critical` | `flag` | Return non-zero exit code (1) if any CRITICAL control fails (ideal for CI/CD gates) |
| `--format FMT` | `choice` | Output format: `table` (terminal ASCII) or `json` |
| `--output FILE` | `string` | Write report to file |

---

## 💻 Usage Examples

### 1. Run local multi-cloud posture audit
```bash
python cis_evaluator.py --format table
```
**Sample Output:**
```text
==========================================================================
   CIS BENCHMARKS CSPM POSTURE EVALUATION REPORT
==========================================================================
Overall Compliance Score: 100.0%
Total Controls Tested:    10
Passed Controls:          10
Failed Controls:          0 (Critical Failures: 0)
--------------------------------------------------------------------------
+-+-------------+-------+----------+--------+----------------------------------------------------+
| Control ID    | Cloud | Severity | Status | Control Title                                      |
+-+-------------+-------+----------+--------+----------------------------------------------------+
| CIS-AWS-1.4   | AWS   | CRITICAL | PASS   | Ensure MFA is enabled for the 'root' user account  |
| CIS-AWS-1.10  | AWS   | HIGH     | PASS   | Ensure IAM password policy meets enterprise stren  |
| CIS-AWS-2.1.1 | AWS   | CRITICAL | PASS   | Ensure CloudTrail is enabled across all regions    |
| CIS-AWS-2.1.4 | AWS   | CRITICAL | PASS   | Ensure S3 Public Access Block is enforced globally |
| CIS-AZ-1.1    | Azure | CRITICAL | PASS   | Ensure Multi-Factor Authentication is enforced     |
| CIS-AZ-4.1.1  | Azure | CRITICAL | PASS   | Ensure NSG rules restrict inbound SSH (22) and RDP |
| CIS-AZ-5.1.1  | Azure | HIGH     | PASS   | Ensure Azure Key Vault audit and diagnostic logs   |
+-+-------------+-------+----------+--------+----------------------------------------------------+
==========================================================================
```

### 2. Audit custom environment file and enforce CI/CD compliance gate
```bash
python cis_evaluator.py --input-config samples/aws_azure_inventory.json --fail-on-critical
```

### 3. Inspect repository telemetry posture matrix
```bash
python cis_evaluator.py --matrix benchmarks/cloud_cis_matrix.json
```

---

## 🧪 Unit Testing

Run the automated test suite with standard `unittest`:

```bash
python -m unittest tests/test_cis_evaluator.py
```

---

## 📊 Live Telemetry Matrix

Continuous posture records and compliance scores are updated in:
- [`benchmarks/cloud_cis_matrix.json`](./benchmarks/cloud_cis_matrix.json)
