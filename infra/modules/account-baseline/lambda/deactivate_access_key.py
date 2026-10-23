"""Deactivate every new IAM access key (the Respond layer).

Runs on a successful CreateAccessKey. Deactivates instead of deleting,
so the key stays as evidence.
"""
import boto3

iam = boto3.client("iam")


def handler(event, context):
    key = event["detail"]["responseElements"]["accessKey"]
    iam.update_access_key(
        UserName=key["userName"],
        AccessKeyId=key["accessKeyId"],
        Status="Inactive",
    )
    print(f"Deactivated {key['accessKeyId']} of user {key['userName']}")
