# Boto3 Cloud Security Automation

# Cloud Security & Compliance Automation

Security-first, cloud-agnostic automation framework for
auditing, enforcing, and remediating cloud security and
compliance controls across AWS (and future Azure/GCP).

## What this repo does
- Cloud security audits (IAM, S3, KMS, networking)
- Compliance control evaluation (CIS, ISO 27001, GDPR)
- Automated remediation with guardrails
- Evidence collection for audits

## Design philosophy
- Assume breach
- Least privilege by default
- Prevent > detect > respond
- Compliance as code, not PDFs

## Tech stack
- Python (primary automation language)
- Cloud SDKs (boto3, Azure SDK, GCP SDK – planned)
- OPA / policy-as-code (where applicable)

## Status
🚧 Actively evolving. This repo is intentionally opinionated
and mirrors real-world cloud security constraints.


## 📂 Repository Structure

```text
.
├── README.md
├── iam
│   ├── iam_key_remediation.py
│   └── iam_security_audit.py
├── reports
│   ├── iam_audit_report.csv
│   ├── iam_remediation_log.json
│   ├── s3_audit_report.json
│   ├── s3_compliance_report.json
│   └── s3_recommendations.json
└── s3
    ├── s3_acl_check.py
    ├── s3_acl_recomendations.py
    ├── s3_public_Access.py
    └── s3_remediation_recomendations.py
