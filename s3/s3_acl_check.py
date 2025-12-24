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
    is_public = False

    #  Get ACL for each bucket
    acl = s3.get_bucket_acl(Bucket=bucket_name)

    for grant in acl["Grants"]:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")

        if uri in [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        ]:
            is_public = True

    # PASS / FAIL classification
    status = "FAIL" if is_public else "PASS"

    # Store structured result
    results.append({
        "resource_type": "s3_bucket",
        "bucket_name": bucket_name,
        "check": "acl_public_access",
        "status": status,
        "checked_at": timestamp
    })

# Write JSON report
with open("reports/s3_audit_report.json", "w") as f:
    json.dump(results, f, indent=2)

print("S3 ACL audit report written to reports/s3_audit_report.json")