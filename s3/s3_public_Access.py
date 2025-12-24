import boto3
import json
from datetime import datetime, timezone

s3 = boto3.client("s3")

results = []
timestamp = datetime.now(timezone.utc).isoformat()

# List all buckets
buckets = s3.list_buckets()["Buckets"]

for bucket in buckets:
    bucket_name = bucket["Name"]

    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        # PASS / FAIL logic
        status = "PASS" if all(config.values()) else "FAIL"
        reason = "All public access blocks enabled" if status == "PASS" else "One or more public access blocks disabled"

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        status = "FAIL"
        reason = "No public access block configuration found"

    # Store structured result
    results.append({
        "resource_type": "s3_bucket",
        "bucket_name": bucket_name,
        "check": "public_access_block",
        "status": status,
        "reason": reason,
        "checked_at": timestamp
    })

# Write JSON report (append-friendly design)
with open("reports/s3_compliance_report.json", "w") as f:
    json.dump(results, f, indent=2)

print("S3 Public Access Block audit written to reports/s3_compliance_report.json")