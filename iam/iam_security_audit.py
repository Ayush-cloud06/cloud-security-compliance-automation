import boto3
import csv
from datetime import datetime, timezone

iam = boto3.client("iam")

results = []
timestamp = datetime.now(timezone.utc).isoformat()

response = iam.list_users()
users = response["Users"]

for user in users:
    username = user["UserName"]

      # ACCESS KEY CHECK
  
    keys_response = iam.list_access_keys(UserName=username)
    keys = keys_response["AccessKeyMetadata"]

    if not keys:
        results.append({
            "username": username,
            "check": "access_keys_present",
            "status": "PASS",
            "details": "No access keys",
            "checked_at": timestamp
        })
    else:
        for key in keys:
            created = key["CreateDate"]
            age_days = (datetime.now(timezone.utc) - created).days

            status = "FAIL" if age_days > 90 else "PASS"

            results.append({
                "username": username,
                "check": "access_key_age",
                "status": status,
                "details": f"Key age {age_days} days",
                "checked_at": timestamp
            })

    
    # MFA CHECK
   
    mfa = iam.list_mfa_devices(UserName=username)

    if not mfa["MFADevices"]:
        results.append({
            "username": username,
            "check": "mfa_enabled",
            "status": "FAIL",
            "details": "No MFA device attached",
            "checked_at": timestamp
        })
    else:
        results.append({
            "username": username,
            "check": "mfa_enabled",
            "status": "PASS",
            "details": "MFA enabled",
            "checked_at": timestamp
        })

# WRITE CSV REPORT

with open("reports/iam_audit_report.csv", "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=results[0].keys()
    )
    writer.writeheader()
    writer.writerows(results)

print("IAM audit report written to reports/iam_audit_report.csv")