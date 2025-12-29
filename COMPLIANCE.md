# Compliance and Security Controls

## Overview

This repository implements cloud security controls for AWS and S3 using Python (boto3).
This contrls focus on detecting security misconfigurations, making risk-based decisions,
and generating audit-ready evidence. Enforcement is intentionally limited to avoid 
uncontrolle changes inproduction environments.

---

## Scope

- AWS IAM (identity configuration and ey hygiene)
- Amazon s3 (data exposure and protection controls)

**Out of Scope (by design) :**
 
 - Runtime activity analysis (CloudTrail)
 - Automated large-scale remediation
 - organization-wide policy enforcement

 ---

## Implemented Controls

### IAM controls
- IAM.kEY.ROTATION
- IAM.MFA.ENFORCEMENT

### S3 Controls
- S3.PUBLIC_ACCESS_BLOCK
- S3.PUBLIC_ACL
- S3.ENCRYPTION
- S3.VERSIONING

---

# Evidence And Reports

All controls generated structured, timestamped evidence in machine-readable formats
(JSON / CSV). Evidence files are written to the `reports/` directory and are designed
to be reviewable by auditors, security teams, and automated tooling.

---

## Design Decisions & Limitations

## Standards Mapping (Summary)
