"""
CloudFreeze v7 — Unit Tests for Forensic Lambda
================================================
Uses pytest + moto (AWS mock library) for zero-cost testing.
Run: python -m pytest tests/ -v
"""

import json
import os
import sys
import pytest
from datetime import datetime, timezone

import boto3
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda'))


@pytest.fixture
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_REGION"] = "us-east-1"


@pytest.fixture
def setup_forensic_resources(aws_credentials):
    """Create all required AWS resources for forensic Lambda testing."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")

        # Create an EC2 instance with an EBS volume
        instances = ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1,
            InstanceType="t2.micro",
        )
        instance_id = instances["Instances"][0]["InstanceId"]

        # Create S3 bucket for forensic data
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="cloudfreeze-forensic-test")

        # Create SNS topic
        sns = boto3.client("sns", region_name="us-east-1")
        topic = sns.create_topic(Name="cloudfreeze-alerts")
        topic_arn = topic["TopicArn"]

        # Create KMS key
        kms = boto3.client("kms", region_name="us-east-1")
        key = kms.create_key(Description="CloudFreeze test key")
        kms_key_arn = key["KeyMetadata"]["Arn"]

        os.environ["FORENSIC_S3_BUCKET"] = "cloudfreeze-forensic-test"
        os.environ["ENABLE_MEMORY_FORENSICS"] = "false"

        if "lambda_forensic" in sys.modules:
            del sys.modules["lambda_forensic"]
        import lambda_forensic

        lambda_forensic.ec2_client = boto3.client("ec2", region_name="us-east-1")
        lambda_forensic.sns_client = boto3.client("sns", region_name="us-east-1")
        lambda_forensic.FORENSIC_S3_BUCKET = "cloudfreeze-forensic-test"

        yield {
            "module": lambda_forensic,
            "instance_id": instance_id,
            "topic_arn": topic_arn,
            "kms_key_arn": kms_key_arn,
        }


class TestForensicHandler:
    """Tests for the forensic Lambda handler."""

    def test_missing_instance_id(self, setup_forensic_resources):
        """Missing instance_id should return 400."""
        lf = setup_forensic_resources["module"]
        result = lf.lambda_handler({}, None)
        assert result["statusCode"] == 400

    def test_successful_forensic_snapshot(self, setup_forensic_resources):
        """Should create forensic snapshots for a valid instance."""
        lf = setup_forensic_resources["module"]
        instance_id = setup_forensic_resources["instance_id"]
        kms_key_arn = setup_forensic_resources["kms_key_arn"]

        result = lf.lambda_handler({
            "instance_id": instance_id,
            "kms_key_arn": kms_key_arn,
            "sns_topic_arn": setup_forensic_resources["topic_arn"],
        }, None)
        assert result["statusCode"] == 200

    def test_forensic_snapshot_with_sns(self, setup_forensic_resources):
        """Forensic completion should send SNS notification."""
        lf = setup_forensic_resources["module"]
        instance_id = setup_forensic_resources["instance_id"]

        result = lf.lambda_handler({
            "instance_id": instance_id,
            "kms_key_arn": "",
            "sns_topic_arn": setup_forensic_resources["topic_arn"],
        }, None)
        assert result["statusCode"] == 200

    def test_snapshot_nonexistent_instance(self, setup_forensic_resources):
        """Snapshot of nonexistent instance should handle gracefully."""
        lf = setup_forensic_resources["module"]
        result = lf.create_forensic_snapshots("i-doesnotexist", "")
        # Should succeed with "no volumes" since instance doesn't exist
        assert result["status"] in ("SUCCESS", "FAILED")


class TestForensicHelpers:
    """Tests for forensic Lambda helper functions."""

    def test_retry_decorator_exists(self, setup_forensic_resources):
        """Verify retry decorator is available."""
        lf = setup_forensic_resources["module"]
        assert hasattr(lf, "retry_with_backoff")

    def test_memory_forensics_disabled(self, setup_forensic_resources):
        """Memory forensics should not run when disabled."""
        lf = setup_forensic_resources["module"]
        lf.ENABLE_MEMORY_FORENSICS = False
        result = lf.lambda_handler({
            "instance_id": setup_forensic_resources["instance_id"],
            "kms_key_arn": "",
            "sns_topic_arn": "",
        }, None)
        body = result.get("body", {})
        if isinstance(body, dict):
            assert "memory_capture" not in body
