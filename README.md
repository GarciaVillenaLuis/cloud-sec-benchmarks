# Cloud Security Benchmarks ☁️

Automated compliance baseline checks and **CIS Benchmarks** (Center for Internet Security) posture validation rules for **AWS** and **Microsoft Azure** architectures.

## Standards Covered
- **CIS AWS Foundations Benchmark v3.0.0**: IAM password policy, MFA enforcement, CloudTrail multi-region logging, S3 public access block.
- **CIS Microsoft Azure Foundations Benchmark v2.1.0**: Azure AD conditional access, Network Security Groups (NSGs), Key Vault diagnostic logs.
- **Policy-as-Code**: Formatted JSON/YAML policies compatible with Open Policy Agent (OPA) and Terraform scanning.

## Benchmarks Matrix
Baseline checks and scoring metrics are tracked in [`benchmarks/cloud_cis_matrix.json`](./benchmarks/cloud_cis_matrix.json).
