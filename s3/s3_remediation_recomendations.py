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

        if not all(config.values()):
            results.append({
                "control_id": "S3.PUBLIC_ACCESS_BLOCK",
                "resource_type": "s3_bucket",
                "bucket_name": bucket_name,
                "severity": "HIGH",
                "finding": "Public access block is not fully enabled",
                "recommendation": "Enable all four public access block settings unless explicitly required",
                "mode": "SUGGEST_ONLY",
                "timestamp": timestamp
            })

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        results.append({
            "control_id": "S3.PUBLIC_ACCESS_BLOCK",
            "resource_type": "s3_bucket",
            "bucket_name": bucket_name,
            "severity": "HIGH",
            "finding": "No public access block configuration found",
            "recommendation": "Enable public access block to prevent accidental public exposure",
            "mode": "SUGGEST_ONLY",
            "timestamp": timestamp
        })

# Write recommendation report
with open("reports/s3_recommendations.json", "w") as f:
    json.dump(results, f, indent=2)

print("S3 remediation recommendations written to reports/s3_recommendations.json")
