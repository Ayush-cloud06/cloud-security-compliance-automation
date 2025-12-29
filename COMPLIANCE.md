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

**Risk addressed**
Accidental or unautorized public exposure of data stored in Amazons3 buckets.

**Why this control exists**
Publicly accessible s3 buckets are common cause of data breaces. Even when bucket
policies and ACLs are configured correctly, missing or partially disabled public 
access block settings can allow intended exposure.

**How the control works**
The control enumerates all s3 buckets and evaluated the Public Access Block configuration.
If one or more of the four public access block setting are disabled or missing,
is flagged as a high-severity finding.

**Control behaviour**
- Service : Amazon s3
- Control type: preventive / Detective
- Enforcement: suggest-only
- Severity: High

**Evidence generated**
- JSON findings written to `reports/s3_recommendations.json`
- Each finding includes bucket name, severity, recommendtion, and timestamp

--- 

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
S3 controls are implemented in suggest-only mode to avoid unintended data loss or
service disruption. Enforcement may be introduced in controlled environments with
explicit approval

## Standards Mapping (Summary)
