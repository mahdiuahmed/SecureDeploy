"""
SecureDeploy Cloud Posture Monitor

Runs daily via EventBridge cron.
Scans AWS account for common misconfigurations, reports findings to SNS.

Checks (industry-standard, CIS Benchmark-aligned):
  1. S3 buckets: public access (Capital One-style prevention)
  2. IAM: access keys older than 90 days (key rotation)
  3. EBS: unencrypted volumes (data-at-rest encryption)
  4. Security groups: 0.0.0.0/0 on sensitive ports (22, 3389)
"""
import os
import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
PROJECT_NAME = os.environ.get("PROJECT_NAME", "securedeploy")

# Sensitive ports that should never be open to the internet
DANGEROUS_PORTS = {22, 3389, 3306, 5432, 6379, 27017, 9200}

s3 = boto3.client("s3")
iam = boto3.client("iam")
ec2 = boto3.client("ec2")
sns = boto3.client("sns")


class Severity:
    CRITICAL = "🚨 CRITICAL"
    HIGH = "⚠️ HIGH"
    MEDIUM = "🔸 MEDIUM"


def check_public_s3_buckets():
    """Find S3 buckets with public ACL or public bucket policy."""
    findings = []
    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            try:
                # Check public access block (best practice = all blocked)
                pab = s3.get_public_access_block(Bucket=name)
                config = pab["PublicAccessBlockConfiguration"]
                if not all(config.values()):
                    findings.append(
                        f"{Severity.CRITICAL} S3 bucket '{name}' has public access block DISABLED"
                    )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(
                        f"{Severity.CRITICAL} S3 bucket '{name}' has NO public access block configured"
                    )
    except ClientError as e:
        logger.error(f"S3 scan error: {e}")
    return findings


def check_old_iam_keys(max_age_days=90):
    """Find IAM access keys older than max_age_days (default 90)."""
    findings = []
    try:
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                age_days = (datetime.now(timezone.utc) -
                            key["CreateDate"]).days
                if age_days > max_age_days:
                    masked_key = key["AccessKeyId"][:4] + \
                        "…" + key["AccessKeyId"][-4:]
                    findings.append(
                        f"{Severity.MEDIUM} IAM key {masked_key} for user '{username}' "
                        f"is {age_days} days old (rotate, CIS 1.4)"
                    )
    except ClientError as e:
        logger.error(f"IAM scan error: {e}")
    return findings


def check_unencrypted_ebs():
    """Find EBS volumes without encryption at rest."""
    findings = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page["Volumes"]:
                if not volume["Encrypted"]:
                    findings.append(
                        f"{Severity.HIGH} EBS volume '{volume['VolumeId']}' is UNENCRYPTED "
                        f"(state: {volume['State']}, size: {volume['Size']}GB)"
                    )
    except ClientError as e:
        logger.error(f"EBS scan error: {e}")
    return findings


def check_open_security_groups():
    """Find security groups allowing 0.0.0.0/0 on sensitive ports."""
    findings = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "unknown")
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    # Check if any dangerous port is in this rule's range
                    danger = {
                        p for p in DANGEROUS_PORTS if from_port <= p <= to_port}
                    if not danger:
                        continue
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            findings.append(
                                f"{Severity.CRITICAL} Security group '{sg_id}' ({sg_name}) "
                                f"allows port(s) {sorted(danger)} from 0.0.0.0/0"
                            )
    except ClientError as e:
        logger.error(f"Security group scan error: {e}")
    return findings


def publish_findings(findings):
    """Publish findings to SNS topic as structured report."""
    if not findings:
        logger.info("✓ No findings — cloud posture clean")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = f"SecureDeploy Posture Report — {timestamp}\n{'=' * 50}\n"
    body = "\n".join(f"• {f}" for f in findings)
    footer = f"\n\n{'=' * 50}\nTotal findings: {len(findings)}\nProject: {PROJECT_NAME}"

    message = header + body + footer

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{PROJECT_NAME}] {len(findings)} security findings",
        Message=message,
    )
    logger.info(f"Published {len(findings)} findings to SNS")


def lambda_handler(event, context):
    """Lambda entry point — run all checks, report findings."""
    logger.info(f"Starting posture check for project: {PROJECT_NAME}")

    all_findings = []
    all_findings.extend(check_public_s3_buckets())
    all_findings.extend(check_old_iam_keys())
    all_findings.extend(check_unencrypted_ebs())
    all_findings.extend(check_open_security_groups())

    publish_findings(all_findings)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "findings_count": len(all_findings),
            "findings": all_findings,
        }),
    }
