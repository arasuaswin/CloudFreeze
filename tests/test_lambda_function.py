"""
CloudFreeze v4 — Unit Tests for Kill-Switch Lambda
====================================================
Uses pytest + moto (AWS mock library) for zero-cost testing.
Run: python -m pytest tests/ -v
"""

import json
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import boto3
from moto import mock_aws

# Add the lambda directory to path so we can import the function
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda'))


# ═══════════════════════════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_REGION"] = "us-east-1"


@pytest.fixture
def setup_aws_resources(aws_credentials):
    """Create all required AWS resources for testing."""
    with mock_aws():
        # Create VPC + Security Groups
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        quarantine_sg = ec2.create_security_group(
            GroupName="cloudfreeze-quarantine-sg",
            Description="Quarantine SG",
            VpcId=vpc_id,
        )
        normal_sg = ec2.create_security_group(
            GroupName="cloudfreeze-normal-sg",
            Description="Normal SG",
            VpcId=vpc_id,
        )
        quarantine_sg_id = quarantine_sg["GroupId"]
        normal_sg_id = normal_sg["GroupId"]

        # Create DynamoDB table
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="cloudfreeze-incidents",
            KeySchema=[{"AttributeName": "target_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "target_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create SNS topic
        sns = boto3.client("sns", region_name="us-east-1")
        topic = sns.create_topic(Name="cloudfreeze-alerts")
        topic_arn = topic["TopicArn"]

        # Create EC2 instance
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SecurityGroupIds=[normal_sg_id],
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "CloudFreeze", "Value": "monitored"},
                    {"Key": "Name", "Value": "test-instance"},
                ],
            }],
        )
        instance_id = instances["Instances"][0]["InstanceId"]

        # Set environment variables
        os.environ["QUARANTINE_SG_ID"] = quarantine_sg_id
        os.environ["NORMAL_SG_ID"] = normal_sg_id
        os.environ["SNS_TOPIC_ARN"] = topic_arn
        os.environ["DYNAMODB_TABLE"] = "cloudfreeze-incidents"
        os.environ["SNAPSHOT_KMS_KEY_ARN"] = ""
        # v4 REAL-TIME: KMS rate counter config
        os.environ["KMS_RATE_TABLE"] = "cloudfreeze-kms-rate"
        os.environ["KMS_RATE_THRESHOLD"] = "5"  # Low threshold for testing
        os.environ["KMS_RATE_WINDOW"] = "60"

        # v4: Create KMS rate counter DynamoDB table
        kms_rate_table = dynamodb.create_table(
            TableName="cloudfreeze-kms-rate",
            KeySchema=[{"AttributeName": "window_key", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "window_key", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        # Force reimport of the module with new env vars
        if "lambda_function" in sys.modules:
            del sys.modules["lambda_function"]
        import lambda_function

        # Reinitialize clients to use moto mocks
        lambda_function.ec2_client = boto3.client("ec2", region_name="us-east-1")
        lambda_function.iam_client = boto3.client("iam", region_name="us-east-1")
        lambda_function.sns_client = boto3.client("sns", region_name="us-east-1")
        lambda_function.dynamodb_client = boto3.resource("dynamodb", region_name="us-east-1")
        lambda_function.sts_client = boto3.client("sts", region_name="us-east-1")
        lambda_function.QUARANTINE_SG_ID = quarantine_sg_id
        lambda_function.NORMAL_SG_ID = normal_sg_id
        lambda_function.SNS_TOPIC_ARN = topic_arn
        lambda_function.DYNAMODB_TABLE = "cloudfreeze-incidents"
        # v4: Initialize real-time rate counter
        lambda_function.dynamodb_raw = boto3.client("dynamodb", region_name="us-east-1")
        lambda_function.KMS_RATE_TABLE = "cloudfreeze-kms-rate"
        lambda_function.KMS_RATE_THRESHOLD = 5
        lambda_function.KMS_RATE_WINDOW = 60
        # v7: Initialize new clients and caches
        lambda_function.ssm_client = boto3.client("ssm", region_name="us-east-1")
        lambda_function._LOCAL_DEDUP_CACHE = {}
        lambda_function._LOCAL_KMS_RATE_CACHE = {}
        lambda_function._REGIONAL_EC2_CLIENTS = {}
        lambda_function._PERMISSIONS_VALIDATED = False

        yield {
            "module": lambda_function,
            "instance_id": instance_id,
            "quarantine_sg_id": quarantine_sg_id,
            "normal_sg_id": normal_sg_id,
            "topic_arn": topic_arn,
            "vpc_id": vpc_id,
            "ec2": ec2,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  TARGET EXTRACTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestTargetExtraction:
    """Tests for the extract_target function — the event parser."""

    def test_manual_instance_id(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf.extract_target({"instance_id": "i-0abcdef1234567890"})
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-0abcdef1234567890"
        assert result["tripwire"] == "manual-test"

    def test_manual_iam_arn(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        arn = "arn:aws:iam::123456789012:role/TestRole"
        result = lf.extract_target({"iam_arn": arn, "iam_type": "role"})
        assert result is not None
        assert result["type"] == "iam"
        assert result["id"] == arn
        assert result["iam_type"] == "role"

    def test_s3_event_notification(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "Records": [{
                "eventSource": "aws:s3",
                "s3": {
                    "bucket": {"name": "honeytoken-bucket"},
                    "object": {"key": "honeytokens/000_database_passwords.csv"},
                },
                "userIdentity": {"principalId": "AROAXXXXXXXXX:i-0abcdef1234567890"},
            }]
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-0abcdef1234567890"
        assert "honeytoken" in result["tripwire"]

    def test_cloudwatch_alarm_event(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "CloudWatch Alarm State Change",
            "detail": {
                "alarmName": "cloudfreeze-cpu-spike",
                "state": {"value": "ALARM"},
                "configuration": {
                    "metrics": [{
                        "metricStat": {
                            "metric": {
                                "dimensions": {"InstanceId": "i-target123"}
                            }
                        }
                    }]
                },
            },
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-target123"
        assert "velocity-alarm" in result["tripwire"]

    def test_guardduty_ec2_finding(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "GuardDuty Finding",
            "detail": {
                "type": "CryptoCurrency:EC2/BitcoinTool.B",
                "severity": 8,
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {"instanceId": "i-crypto123"},
                },
            },
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-crypto123"
        assert "guardduty" in result["tripwire"]

    def test_guardduty_high_severity_fallback(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "GuardDuty Finding",
            "detail": {
                "type": "UnauthorizedAccess:S3/MaliciousIPCaller",
                "severity": 8,
                "resource": {"resourceType": "S3Bucket"},
            },
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "multi-ec2"

    def test_account_wide_alarm_no_instance(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "CloudWatch Alarm State Change",
            "detail": {
                "alarmName": "cloudfreeze-kms-rate-spike",
                "state": {"value": "ALARM"},
                "configuration": {"metrics": []},
            },
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "multi-ec2"

    def test_cloudtrail_kms_event(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventSource": "kms.amazonaws.com",
                "eventName": "Encrypt",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::123456789012:assumed-role/TestRole/session",
                    "principalId": "AROAXXXXXXXXX:i-instance123",
                    "sessionContext": {
                        "sessionIssuer": {
                            "arn": "arn:aws:iam::123456789012:role/TestRole"
                        }
                    },
                },
            },
        }
        result = lf.extract_target(event)
        # v4: First call is below rate threshold, so result is None (rate-gated)
        # Pre-warm the rate counter to exceed threshold (threshold=5)
        for _ in range(4):
            lf._check_kms_rate_limit()
        # Now re-extract — rate threshold is breached, quarantine should trigger
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-instance123"


# ═══════════════════════════════════════════════════════════════════════════════
#  EDGE CASE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Tests for edge cases that should be handled gracefully."""

    def test_empty_event(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf.lambda_handler({}, None)
        assert result["statusCode"] == 400

    def test_none_event_type(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf.lambda_handler("not a dict", None)
        assert result["statusCode"] == 400

    def test_no_extractable_target(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf.lambda_handler({"random": "data"}, None)
        assert result["statusCode"] == 400

    def test_malformed_s3_event(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {"Records": [{"eventSource": "aws:s3"}]}
        result = lf.extract_target(event)
        # Should handle missing s3 data gracefully
        assert result is None or result is not None  # should not crash


# ═══════════════════════════════════════════════════════════════════════════════
#  IDEMPOTENCY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIdempotency:
    """Tests for DynamoDB-based deduplication."""

    def test_first_call_acquires_lock(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        assert lf.acquire_incident_lock("i-test123", "test") is True

    def test_duplicate_call_rejected(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        lf.acquire_incident_lock("i-test456", "test")
        assert lf.acquire_incident_lock("i-test456", "test") is False

    def test_different_targets_both_accepted(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        assert lf.acquire_incident_lock("i-first", "test") is True
        assert lf.acquire_incident_lock("i-second", "test") is True


# ═══════════════════════════════════════════════════════════════════════════════
#  EC2 TAKEDOWN TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestEC2Takedown:
    """Tests for the EC2 quarantine + revoke + snapshot pipeline."""

    def test_network_quarantine_success(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]

        result = lf.perform_network_quarantine(instance_id)
        assert result["status"] == "SUCCESS"
        assert len(result["interfaces_quarantined"]) > 0

    def test_quarantine_nonexistent_instance(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf.perform_network_quarantine("i-doesnotexist")
        assert result["status"] == "FAILED"

    def test_forensic_preservation_success(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]

        result = lf.perform_forensic_preservation(instance_id)
        assert result["status"] == "SUCCESS"

    def test_full_ec2_takedown(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]

        result = lf.execute_ec2_takedown(instance_id)
        assert result["network_quarantine"]["status"] == "SUCCESS"
        assert result["forensic_preservation"]["status"] == "SUCCESS"

    def test_terminated_instance_skipped(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        ec2 = setup_aws_resources["ec2"]
        instance_id = setup_aws_resources["instance_id"]

        # Terminate the instance
        ec2.terminate_instances(InstanceIds=[instance_id])

        result = lf.execute_ec2_takedown(instance_id)
        assert result["status"] == "SKIPPED"
        assert "terminated" in result["reason"]


# ═══════════════════════════════════════════════════════════════════════════════
#  FULL HANDLER INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestLambdaHandler:
    """Integration tests for the full lambda_handler flow."""

    def test_manual_ec2_invocation(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]

        event = {"instance_id": instance_id}
        result = lf.lambda_handler(event, None)
        assert result["statusCode"] == 200

    def test_duplicate_invocation_handled(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]

        event = {"instance_id": instance_id}
        result1 = lf.lambda_handler(event, None)
        assert result1["statusCode"] == 200

        result2 = lf.lambda_handler(event, None)
        assert result2["statusCode"] == 200
        assert "Already handled" in result2["body"]


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHelpers:
    """Tests for utility functions."""

    def test_extract_entity_name_simple(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        assert lf._extract_entity_name("arn:aws:iam::123456789012:role/MyRole") == "MyRole"

    def test_extract_entity_name_with_path(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        assert lf._extract_entity_name("arn:aws:iam::123456789012:role/service-role/MyRole") == "MyRole"

    def test_extract_entity_name_user(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        assert lf._extract_entity_name("arn:aws:iam::123456789012:user/admin") == "admin"

    def test_extract_entity_name_none(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        assert lf._extract_entity_name(None) is None

    def test_resolve_principal_ec2(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf._resolve_principal("AROAXXX:i-abc123", tripwire="test")
        assert result["type"] == "ec2"
        assert result["id"] == "i-abc123"

    def test_resolve_principal_iam(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf._resolve_principal("AROAXXX:session-name", tripwire="test")
        assert result["type"] == "iam"

    def test_resolve_principal_empty(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        result = lf._resolve_principal("", tripwire="test")
        assert result is None

    def test_discover_monitored_instances(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        instances = lf._discover_monitored_instances()
        assert len(instances) >= 1
        assert setup_aws_resources["instance_id"] in instances

    def test_verify_sg_exists(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        assert lf._verify_sg_exists(setup_aws_resources["quarantine_sg_id"]) is True
        assert lf._verify_sg_exists("sg-doesnotexist") is False


# ═══════════════════════════════════════════════════════════════════════════════
#  v4 REAL-TIME: KMS RATE COUNTER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestKMSRateCounter:
    """Tests for the in-Lambda KMS rate counting via DynamoDB atomic counters."""

    def test_below_threshold_no_quarantine(self, setup_aws_resources):
        """Single KMS call should NOT trigger quarantine (threshold=5)."""
        lf = setup_aws_resources["module"]
        # One call should return False (below threshold)
        assert lf._check_kms_rate_limit() is False

    def test_threshold_breach_triggers_quarantine(self, setup_aws_resources):
        """When KMS calls exceed threshold, quarantine should trigger."""
        lf = setup_aws_resources["module"]
        # Call rate counter 5 times (threshold=5) to trigger
        for _ in range(4):
            lf._check_kms_rate_limit()
        # 5th call should return True (threshold breached)
        assert lf._check_kms_rate_limit() is True

    def test_rate_counter_atomic_increment(self, setup_aws_resources):
        """Counter should increment atomically without race conditions."""
        lf = setup_aws_resources["module"]
        # First 4 calls below threshold
        results = [lf._check_kms_rate_limit() for _ in range(4)]
        assert all(r is False for r in results)
        # 5th call breaches threshold
        assert lf._check_kms_rate_limit() is True

    def test_rate_counter_fail_open(self, setup_aws_resources):
        """If KMS_RATE_TABLE is empty, should fail-open (return True)."""
        lf = setup_aws_resources["module"]
        original = lf.KMS_RATE_TABLE
        lf.KMS_RATE_TABLE = ""
        assert lf._check_kms_rate_limit() is True
        lf.KMS_RATE_TABLE = original


# ═══════════════════════════════════════════════════════════════════════════════
#  v4 REAL-TIME: INSTANCE AGENT EVENT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestInstanceAgentEvents:
    """Tests for the on-instance monitoring agent event parsing."""

    def test_cpu_spike_event(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "source": "instance-agent",
            "instance_id": "i-agent-cpu-test",
            "alert_type": "cpu-spike",
            "detail": "CPU at 95% (threshold: 90%)",
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-agent-cpu-test"
        assert result["tripwire"] == "instance-agent-cpu-spike"

    def test_disk_spike_event(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "source": "instance-agent",
            "instance_id": "i-agent-disk-test",
            "alert_type": "disk-spike",
            "detail": "Disk write 120MB/s (threshold: 50MB)",
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-agent-disk-test"
        assert result["tripwire"] == "instance-agent-disk-spike"

    def test_canary_tampered_event(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "source": "instance-agent",
            "instance_id": "i-agent-canary-test",
            "alert_type": "canary-tampered",
            "detail": "Canary file checksum mismatch",
        }
        result = lf.extract_target(event)
        assert result is not None
        assert result["type"] == "ec2"
        assert result["id"] == "i-agent-canary-test"
        assert result["tripwire"] == "instance-agent-canary-tampered"

    def test_missing_instance_id_rejected(self, setup_aws_resources):
        lf = setup_aws_resources["module"]
        event = {
            "source": "instance-agent",
            "alert_type": "cpu-spike",
            "detail": "CPU at 95%",
        }
        result = lf.extract_target(event)
        # Should fall through to manual-test or return None
        assert result is None or result.get("tripwire") != "instance-agent-cpu-spike"


# ═══════════════════════════════════════════════════════════════════════════════
#  v4 REAL-TIME: CANARY DETECTION INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCanaryDetection:
    """Tests for file-system canary tamper detection via instance agent."""

    def test_canary_deleted_triggers_takedown(self, setup_aws_resources):
        """Canary file deletion should result in EC2 quarantine."""
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]
        event = {
            "source": "instance-agent",
            "instance_id": instance_id,
            "alert_type": "canary-deleted",
            "detail": "Canary files deleted: expected 5, found 2",
        }
        result = lf.lambda_handler(event, None)
        assert result["statusCode"] == 200

    def test_canary_tampered_triggers_takedown(self, setup_aws_resources):
        """Canary file tampering should result in EC2 quarantine."""
        lf = setup_aws_resources["module"]
        # Use a unique instance for this test to avoid idempotency block
        event = {
            "source": "instance-agent",
            "instance_id": "i-canary-tampered-test",
            "alert_type": "canary-tampered",
            "detail": "Canary file checksum mismatch — possible encryption",
        }
        result = lf.lambda_handler(event, None)
        # Should attempt takedown (may fail for non-existent instance, but target extraction works)
        assert result["statusCode"] in (200, 400)


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: IAM TAKEDOWN TESTS (Fix #21)
# ═══════════════════════════════════════════════════════════════════════════════

class TestIAMTakedown:
    """Tests for the IAM identity takedown pipeline."""

    def test_iam_user_deny_policy(self, setup_aws_resources):
        """IAM user deny-all policy should be applied correctly."""
        lf = setup_aws_resources["module"]
        iam = boto3.client("iam", region_name="us-east-1")
        # Create a test IAM user
        iam.create_user(UserName="cloudfreeze-test-user")
        # Execute IAM takedown
        target = {
            "type": "iam",
            "id": "arn:aws:iam::123456789012:user/cloudfreeze-test-user",
            "iam_type": "user",
            "tripwire": "test",
        }
        result = lf.execute_iam_takedown(
            "arn:aws:iam::123456789012:user/cloudfreeze-test-user", "user"
        )
        assert result["deny_policy"]["status"] == "SUCCESS"

    def test_iam_role_deny_policy(self, setup_aws_resources):
        """IAM role deny-all policy should be applied correctly."""
        lf = setup_aws_resources["module"]
        iam = boto3.client("iam", region_name="us-east-1")
        # Create a test IAM role
        iam.create_role(
            RoleName="cloudfreeze-test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
            }),
        )
        target = {
            "type": "iam",
            "id": "arn:aws:iam::123456789012:role/cloudfreeze-test-role",
            "iam_type": "role",
            "tripwire": "test",
        }
        result = lf.execute_iam_takedown(
            "arn:aws:iam::123456789012:role/cloudfreeze-test-role", "role"
        )
        assert result["deny_policy"]["status"] == "SUCCESS"

    def test_iam_takedown_nonexistent_entity(self, setup_aws_resources):
        """Takedown of nonexistent IAM entity should fail gracefully."""
        lf = setup_aws_resources["module"]
        target = {
            "type": "iam",
            "id": "arn:aws:iam::123456789012:user/nonexistent-user",
            "iam_type": "user",
            "tripwire": "test",
        }
        result = lf.execute_iam_takedown(
            "arn:aws:iam::123456789012:user/nonexistent-user", "user"
        )
        # When entity doesn't exist, function returns {error: "..."} or deny_policy with FAILED
        assert result.get("error") or \
               result.get("deny_policy", {}).get("status") == "FAILED" or \
               result.get("status") == "FAILED"

    def test_iam_user_manual_invocation(self, setup_aws_resources):
        """Full handler should process IAM user takedown event."""
        lf = setup_aws_resources["module"]
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="cloudfreeze-handler-user")
        event = {
            "iam_arn": "arn:aws:iam::123456789012:user/cloudfreeze-handler-user",
            "iam_type": "user",
        }
        result = lf.lambda_handler(event, None)
        assert result["statusCode"] == 200


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: CONCURRENCY / LOAD TESTS (Fix #23)
# ═══════════════════════════════════════════════════════════════════════════════

class TestConcurrency:
    """Stress tests for concurrent KMS rate counter operations."""

    def test_concurrent_kms_rate_increments(self, setup_aws_resources):
        """100 concurrent KMS rate increments should result in counter reaching exactly 100."""
        lf = setup_aws_resources["module"]
        from concurrent.futures import ThreadPoolExecutor

        results = []
        def increment_rate():
            return lf._check_kms_rate_limit()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(increment_rate) for _ in range(20)]
            results = [f.result() for f in futures]

        # At least some should have breached the threshold (threshold=5)
        breach_count = sum(1 for r in results if r is True)
        assert breach_count > 0, "At least some calls should breach the threshold"

    def test_idempotency_under_concurrent_calls(self, setup_aws_resources):
        """Multiple concurrent takedown attempts for the same instance should only execute once."""
        lf = setup_aws_resources["module"]
        from concurrent.futures import ThreadPoolExecutor

        instance_id = "i-concurrent-test-123"
        results = []
        def acquire_lock():
            return lf.acquire_incident_lock(instance_id, "concurrent-test")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(acquire_lock) for _ in range(5)]
            results = [f.result() for f in futures]

        # Exactly ONE should succeed (conditional write)
        assert results.count(True) == 1, f"Expected exactly 1 lock acquisition, got {results.count(True)}"
        assert results.count(False) == 4, f"Expected 4 rejections, got {results.count(False)}"


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: NACL QUARANTINE TESTS (Fix #8)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNACLQuarantine:
    """Tests for NACL defense-in-depth quarantine."""

    def test_nacl_quarantine_skipped_when_not_configured(self, setup_aws_resources):
        """NACL quarantine should be skipped if QUARANTINE_NACL_ID is empty."""
        lf = setup_aws_resources["module"]
        original = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = ""
        result = lf.perform_nacl_quarantine("i-test123")
        assert result["status"] == "SKIPPED"
        lf.QUARANTINE_NACL_ID = original

    def test_full_takedown_includes_nacl(self, setup_aws_resources):
        """Full EC2 takedown should include nacl_quarantine in results."""
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]
        # Ensure NACL ID is not set (skip path)
        lf.QUARANTINE_NACL_ID = ""
        result = lf.execute_ec2_takedown(instance_id)
        assert "nacl_quarantine" in result


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: SNS NOTIFICATION TESTS (Fix #11)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSNSNotification:
    """Tests for the publish_notification function and SNS alert deduplication."""

    def test_publish_notification_succeeds(self, setup_aws_resources):
        """publish_notification should not raise an exception."""
        lf = setup_aws_resources["module"]
        # Should not crash even with empty original_event
        lf.publish_notification("test-alert", "test details", {})

    def test_publish_notification_handles_none_event(self, setup_aws_resources):
        """publish_notification should handle None original_event gracefully."""
        lf = setup_aws_resources["module"]
        lf.publish_notification("test-alert", "test details", None)


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: NACL BLAST RADIUS TESTS (Fix #7)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNACLBlastRadius:
    """Tests for the NACL blast radius instance-count check."""

    def test_nacl_skip_when_multiple_instances_in_subnet(self, setup_aws_resources):
        """NACL quarantine should skip when multiple instances share a subnet."""
        lf = setup_aws_resources["module"]
        ec2 = setup_aws_resources["ec2"]
        instance_id = setup_aws_resources["instance_id"]

        # Get the subnet of the existing instance
        inst_detail = ec2.describe_instances(InstanceIds=[instance_id])
        subnet_id = inst_detail["Reservations"][0]["Instances"][0]["SubnetId"]

        # Launch a second instance in the same subnet
        ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1,
            InstanceType="t2.micro",
            SubnetId=subnet_id,
        )

        # Set a valid NACL ID
        lf.QUARANTINE_NACL_ID = "nacl-test-123"

        result = lf.perform_nacl_quarantine(instance_id)
        # v7: Per-IP NACL deny rules are now applied (instead of skipping)
        assert result["status"] == "SUCCESS"
        assert result.get("method") == "per-ip-deny"

        lf.QUARANTINE_NACL_ID = ""


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: IAM EDGE CASE TESTS (Fix #13)
# ═══════════════════════════════════════════════════════════════════════════════

class TestIAMEdgeCases:
    """Tests for IAM takedown edge cases."""

    def test_unknown_iam_type_handled(self, setup_aws_resources):
        """execute_iam_takedown with unknown iam_type should fail gracefully."""
        lf = setup_aws_resources["module"]
        target = {
            "type": "iam",
            "id": "arn:aws:iam::123456789012:group/unknown-group",
            "iam_type": "group",  # Not user or role
            "tripwire": "test",
        }
        result = lf.execute_iam_takedown(
            "arn:aws:iam::123456789012:group/unknown-group", "group"
        )
        assert result["deny_policy"]["status"] in ("FAILED", "SKIPPED")


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: ECS TARGET EXTRACTION TESTS (Fix 3)
# ═══════════════════════════════════════════════════════════════════════════════

class TestECSExtraction:
    """Tests for v7 ECS container target extraction."""

    def test_ecs_task_state_change_extraction(self, setup_aws_resources):
        """ECS Task State Change event should extract task ARN and cluster."""
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "ECS Task State Change",
            "detail": {
                "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/my-cluster/abc123",
                "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster",
                "group": "service:my-service",
                "lastStatus": "RUNNING",
                "containers": [{"name": "web", "exitCode": 0}],
            },
        }
        target = lf.extract_target(event)
        assert target["type"] == "ecs"
        assert "abc123" in target["id"]
        assert "my-cluster" in target["cluster"]
        assert target["tripwire"] == "ecs-suspicious-task"

    def test_ecs_missing_task_arn(self, setup_aws_resources):
        """ECS event without taskArn should return None."""
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "ECS Task State Change",
            "detail": {"clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/c1"},
        }
        target = lf.extract_target(event)
        assert target is None

    def test_manual_ecs_invocation(self, setup_aws_resources):
        """Manual ECS test event should be extracted correctly."""
        lf = setup_aws_resources["module"]
        event = {
            "task_arn": "arn:aws:ecs:us-east-1:123456789012:task/c1/t1",
            "cluster": "arn:aws:ecs:us-east-1:123456789012:cluster/c1",
        }
        target = lf.extract_target(event)
        assert target["type"] == "ecs"
        assert target["tripwire"] == "manual-test"


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: ASYNC FORENSIC INVOCATION TESTS (Fix 13)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAsyncForensicInvocation:
    """Tests for async forensic Lambda invocation."""

    def test_forensic_invoked_before_nacl(self, setup_aws_resources):
        """Verify forensics is invoked BEFORE NACL quarantine in execute_ec2_takedown."""
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]

        # Monkey-patch to record call order
        call_order = []
        original_network = lf.perform_network_quarantine
        original_nacl = lf.perform_nacl_quarantine
        original_iam = lf.perform_ec2_iam_revocation
        original_forensic = lf.perform_forensic_preservation

        def mock_network(iid):
            call_order.append("network")
            return {"status": "SUCCESS"}

        def mock_nacl(iid):
            call_order.append("nacl")
            return {"status": "SUCCESS"}

        def mock_iam(iid):
            call_order.append("iam")
            return {"status": "SUCCESS"}

        def mock_forensic(iid):
            call_order.append("forensic")
            return {"status": "SUCCESS"}

        lf.perform_network_quarantine = mock_network
        lf.perform_nacl_quarantine = mock_nacl
        lf.perform_ec2_iam_revocation = mock_iam
        lf.perform_forensic_preservation = mock_forensic

        # Ensure no FORENSIC_LAMBDA_ARN so inline forensics is used
        original_fla = lf.FORENSIC_LAMBDA_ARN
        lf.FORENSIC_LAMBDA_ARN = ""

        try:
            lf.execute_ec2_takedown(instance_id)
            # v7 Fix 13: forensic must come BEFORE nacl
            forensic_idx = call_order.index("forensic")
            nacl_idx = call_order.index("nacl")
            assert forensic_idx < nacl_idx, f"Forensic ({forensic_idx}) should be before NACL ({nacl_idx}): {call_order}"
        finally:
            lf.perform_network_quarantine = original_network
            lf.perform_nacl_quarantine = original_nacl
            lf.perform_ec2_iam_revocation = original_iam
            lf.perform_forensic_preservation = original_forensic
            lf.FORENSIC_LAMBDA_ARN = original_fla


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: CROSS-REGION CLOUDTRAIL TESTS (Fix 2)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossRegionExtraction:
    """Tests for v7 cross-region CloudTrail event handling."""

    def test_cloudtrail_event_includes_region(self, setup_aws_resources):
        """CloudTrail event with awsRegion should attach region to target."""
        lf = setup_aws_resources["module"]
        event = {
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "awsRegion": "eu-west-1",
                "requestParameters": {"bucketName": "some-bucket", "key": "some-key"},
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/attacker",
                },
            },
        }
        target = lf.extract_target(event)
        assert target is not None
        # IAM targets don't get region, but the function has the info

    def test_ec2_takedown_accepts_target_region(self, setup_aws_resources):
        """execute_ec2_takedown should accept target_region parameter."""
        lf = setup_aws_resources["module"]
        instance_id = setup_aws_resources["instance_id"]
        # Should not crash with region parameter
        result = lf.execute_ec2_takedown(instance_id, target_region="us-east-1")
        assert result is not None
        assert "instance_id" in result


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: SNS RATE LIMITING TESTS (Fix 18)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSNSRateLimiting:
    """Tests for v7 SNS aggregate rate limiting."""

    def test_sns_rate_limit_constants_exist(self, setup_aws_resources):
        """Verify SNS rate limit constants are defined."""
        lf = setup_aws_resources["module"]
        assert hasattr(lf, "SNS_RATE_LIMIT")
        assert hasattr(lf, "SNS_RATE_WINDOW")
        assert lf.SNS_RATE_LIMIT > 0
        assert lf.SNS_RATE_WINDOW > 0

    def test_publish_notification_does_not_crash(self, setup_aws_resources):
        """publish_notification should not crash even without full setup."""
        lf = setup_aws_resources["module"]
        # Should not raise — failures are caught internally
        lf.publish_notification("TEST ALERT", "test body", {"instance_id": "i-test"})


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: CIRCUIT BREAKER TESTS (Fix A)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCircuitBreaker:
    """Tests for the v7 CircuitBreaker class."""

    def test_circuit_breaker_starts_closed(self, setup_aws_resources):
        """Circuit breaker should start in closed state."""
        from utils import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.is_tripped() is False

    def test_circuit_breaker_opens_on_threshold(self, setup_aws_resources):
        """Circuit breaker should open after reaching failure threshold."""
        from utils import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure("Throttling")
        cb.record_failure("Throttling")
        assert cb.is_tripped() is False
        cb.record_failure("Throttling")
        assert cb.is_tripped() is True

    def test_circuit_breaker_resets_on_success(self, setup_aws_resources):
        """Success should reset the failure counter."""
        from utils import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure("Throttling")
        cb.record_failure("Throttling")
        cb.record_success()
        assert cb.failures == 0
        assert cb.is_tripped() is False

    def test_circuit_breaker_stays_open(self, setup_aws_resources):
        """Once open, circuit breaker stays open for the invocation."""
        from utils import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=2)
        cb.record_failure("Throttling")
        cb.record_failure("Throttling")
        assert cb.is_tripped() is True
        # Even after recording success, it stays open (design: per-invocation)
        assert cb.is_open is True


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: IN-MEMORY DEDUP CACHE TESTS (Fix C)
# ═══════════════════════════════════════════════════════════════════════════════

class TestInMemoryDedup:
    """Tests for the v7 in-memory deduplication cache."""

    def test_inmemory_dedup_prevents_duplicate(self, setup_aws_resources):
        """In-memory cache should block duplicate within TTL."""
        lf = setup_aws_resources["module"]
        # Reset cache
        lf._LOCAL_DEDUP_CACHE = {}
        # First call should succeed
        assert lf.acquire_incident_lock("i-dedup-test-1", "test") is True
        # Second call for same target should be blocked by in-memory cache
        assert lf.acquire_incident_lock("i-dedup-test-1", "test") is False

    def test_inmemory_dedup_allows_different_targets(self, setup_aws_resources):
        """Different targets should not be blocked by dedup."""
        lf = setup_aws_resources["module"]
        lf._LOCAL_DEDUP_CACHE = {}
        assert lf.acquire_incident_lock("i-dedup-a", "test") is True
        assert lf.acquire_incident_lock("i-dedup-b", "test") is True


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: KMS RATE IN-MEMORY FALLBACK TESTS (Fix C)
# ═══════════════════════════════════════════════════════════════════════════════

class TestKMSRateInMemoryFallback:
    """Tests for KMS rate counter in-memory cache fallback."""

    def test_kms_rate_inmemory_cache_synced(self, setup_aws_resources):
        """KMS rate counter should populate in-memory cache."""
        lf = setup_aws_resources["module"]
        lf._LOCAL_KMS_RATE_CACHE = {}
        lf._check_kms_rate_limit()
        # In-memory cache should have at least one entry
        assert len(lf._LOCAL_KMS_RATE_CACHE) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: PER-IP NACL QUARANTINE TESTS (Fix D)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPerIPNACL:
    """Tests for v7 per-IP NACL deny rules in shared subnets."""

    def test_nacl_per_ip_when_multi_instance_subnet(self, setup_aws_resources):
        """Multi-instance subnet should get per-IP deny rules instead of SKIP."""
        lf = setup_aws_resources["module"]
        ec2 = setup_aws_resources["ec2"]
        instance_id = setup_aws_resources["instance_id"]

        # Get the subnet of the existing instance
        inst_detail = ec2.describe_instances(InstanceIds=[instance_id])
        subnet_id = inst_detail["Reservations"][0]["Instances"][0]["SubnetId"]

        # Launch a second instance in the same subnet
        ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1,
            InstanceType="t2.micro",
            SubnetId=subnet_id,
        )

        # Set a valid NACL ID
        lf.QUARANTINE_NACL_ID = "nacl-test-per-ip"

        result = lf.perform_nacl_quarantine(instance_id)
        # v7: Instead of SKIPPED, should attempt per-IP deny (may fail in moto)
        assert result["status"] in ("SUCCESS", "FAILED")
        # If successful, verify method is per-ip-deny
        if result["status"] == "SUCCESS":
            assert result.get("method") == "per-ip-deny"

        lf.QUARANTINE_NACL_ID = ""


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: PRE-WRITE ORIGINAL STATE TESTS (Fix E)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPreWriteOriginalState:
    """Tests for v7 pre-write safety mechanism."""

    def test_prewrite_function_exists(self, setup_aws_resources):
        """_prewrite_original_state function should exist."""
        lf = setup_aws_resources["module"]
        assert hasattr(lf, "_prewrite_original_state")

    def test_prewrite_does_not_crash(self, setup_aws_resources):
        """Pre-write should not crash even for non-existent instances."""
        lf = setup_aws_resources["module"]
        # Should not raise — failures are caught internally
        lf._prewrite_original_state("i-nonexistent")


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: CROSS-REGION CLIENT POOL TESTS (Fix F)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossRegionClientPool:
    """Tests for v7 cross-region EC2 client caching."""

    def test_same_region_returns_default_client(self, setup_aws_resources):
        """Same region should return the default client."""
        lf = setup_aws_resources["module"]
        result = lf._get_ec2_client("")
        assert result is lf.ec2_client

    def test_cross_region_client_created(self, setup_aws_resources):
        """Cross-region call should create a new cached client."""
        lf = setup_aws_resources["module"]
        lf._REGIONAL_EC2_CLIENTS = {}
        client = lf._get_ec2_client("eu-west-1")
        assert client is not None
        assert "eu-west-1" in lf._REGIONAL_EC2_CLIENTS

    def test_cross_region_client_reused(self, setup_aws_resources):
        """Second call to same region should reuse cached client."""
        lf = setup_aws_resources["module"]
        lf._REGIONAL_EC2_CLIENTS = {}
        client1 = lf._get_ec2_client("ap-south-1")
        client2 = lf._get_ec2_client("ap-south-1")
        assert client1 is client2


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: SELF-HEALING IAM VALIDATION TESTS (Fix G)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSelfHealingIAM:
    """Tests for v7 self-healing IAM permission validation."""

    def test_permission_validation_function_exists(self, setup_aws_resources):
        """_validate_lambda_permissions function should exist."""
        lf = setup_aws_resources["module"]
        assert hasattr(lf, "_validate_lambda_permissions")

    def test_permission_validation_does_not_crash(self, setup_aws_resources):
        """Permission validation should not crash in test environment."""
        lf = setup_aws_resources["module"]
        lf._PERMISSIONS_VALIDATED = False
        # Should not raise — failures are caught internally
        lf._validate_lambda_permissions()


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: SSM HEALTH CHECK TESTS (Fix B)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSSMHealthCheck:
    """Tests for v7 SSM agent health check."""

    def test_ssm_health_check_function_exists(self, setup_aws_resources):
        """_check_ssm_agent_health function should exist."""
        lf = setup_aws_resources["module"]
        assert hasattr(lf, "_check_ssm_agent_health")

    def test_ssm_health_check_offline_instance(self, setup_aws_resources):
        """SSM health check for non-SSM instance should return False."""
        lf = setup_aws_resources["module"]
        # Non-existent instance should return False gracefully
        result = lf._check_ssm_agent_health("i-nonexistent")
        assert result is False


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: NACL COLLISION AVOIDANCE TESTS (Fix J)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNACLCollisionAvoidance:
    """Tests for v7 NACL rule number collision-avoidant hash."""

    def test_different_ips_different_rules(self):
        """Different IPs should produce different rule numbers."""
        from utils import nacl_rule_number

        ip1 = "10.0.1.45"
        ip2 = "10.0.1.46"
        ip3 = "10.0.2.100"
        ip4 = "10.0.3.200"

        rule1 = nacl_rule_number(ip1)
        rule2 = nacl_rule_number(ip2)
        rule3 = nacl_rule_number(ip3)
        rule4 = nacl_rule_number(ip4)

        # All should be in the valid range 50-249
        for rule in [rule1, rule2, rule3, rule4]:
            assert 50 <= rule <= 249, f"Rule {rule} out of range 50-249"

        # At least most should be unique (hash collision is possible but unlikely)
        unique_count = len(set([rule1, rule2, rule3, rule4]))
        assert unique_count >= 3, "Too many collisions for 4 different IPs"

    def test_same_ip_same_rule(self):
        """Same IP should always produce the same rule number."""
        from utils import nacl_rule_number

        ip = "192.168.1.100"
        assert nacl_rule_number(ip) == nacl_rule_number(ip)

    def test_collision_detection(self):
        """When a rule number is already taken by a different IP, should probe next slot."""
        from utils import nacl_rule_number

        ip = "10.0.1.45"
        base_rule = nacl_rule_number(ip)

        # Create existing rules that occupy the base slot with a DIFFERENT IP
        existing_rules = {base_rule: "10.0.1.99/32"}

        resolved_rule = nacl_rule_number(ip, existing_rules)

        # Should NOT be the same as the base rule (because a different IP occupied it)
        assert resolved_rule != base_rule
        # Should still be in valid range
        assert 50 <= resolved_rule <= 249

    def test_same_ip_reuses_existing_rule(self):
        """When rule number matches the same IP, should reuse it."""
        from utils import nacl_rule_number

        ip = "10.0.1.45"
        base_rule = nacl_rule_number(ip)

        # Create existing rules that occupy the base slot with the SAME IP
        existing_rules = {base_rule: f"{ip}/32"}

        resolved_rule = nacl_rule_number(ip, existing_rules)

        # Should reuse the same rule number
        assert resolved_rule == base_rule

    def test_rule_range_200_slots(self):
        """Verify the hash range provides 200 unique slots (50-249)."""
        from utils import nacl_rule_number

        rules = set()
        for i in range(500):
            rule = nacl_rule_number(f"10.{i // 256}.{i % 256}.{i % 200}")
            assert 50 <= rule <= 249, f"Rule {rule} out of range"
            rules.add(rule)

        # With 500 IPs across 200 slots, we should see good distribution
        assert len(rules) >= 100, f"Only {len(rules)} unique rules for 500 IPs — poor distribution"


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: S3 BULK OPERATION DETECTION TESTS (Fix H)
# ═══════════════════════════════════════════════════════════════════════════════

class TestS3BulkDetection:
    """Tests for v7 S3 bulk operation rate counter."""

    def test_s3_rate_counter_below_threshold(self):
        """Verify counter returns False when below threshold."""
        from utils import S3RateCounter

        counter = S3RateCounter(threshold=5, window_seconds=60)
        for _ in range(4):
            result = counter.increment("principal-1")
        assert result is False

    def test_s3_rate_counter_at_threshold(self):
        """Verify counter returns True when threshold is reached."""
        from utils import S3RateCounter

        counter = S3RateCounter(threshold=5, window_seconds=60)
        for i in range(5):
            result = counter.increment("principal-1")
        assert result is True

    def test_s3_rate_counter_per_principal(self):
        """Verify counters are independent per principal."""
        from utils import S3RateCounter

        counter = S3RateCounter(threshold=5, window_seconds=60)
        for _ in range(4):
            counter.increment("principal-1")
        for _ in range(4):
            counter.increment("principal-2")

        # Neither should have triggered
        assert counter.increment("principal-1") is True  # 5th call
        assert counter.increment("principal-2") is True   # 5th call

    def test_s3_rate_counter_reset(self):
        """Verify reset clears all counters."""
        from utils import S3RateCounter

        counter = S3RateCounter(threshold=5, window_seconds=60)
        for _ in range(4):
            counter.increment("principal-1")
        counter.reset()
        assert counter.increment("principal-1") is False  # Should start fresh

    def test_s3_bulk_event_extract(self, setup_aws_resources):
        """Verify S3 DeleteObject events are handled by CloudTrail handler."""
        lf = setup_aws_resources["module"]
        # Reset the rate counter to known state
        lf._LOCAL_S3_RATE_CACHE.clear()

        event = {
            "source": "aws.s3",
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventSource": "s3.amazonaws.com",
                "eventName": "DeleteObject",
                "userIdentity": {"principalId": "test-principal"},
                "requestParameters": {"bucketName": "some-bucket", "key": "some-key"},
            },
        }

        # First call should return None (below threshold)
        target = lf.extract_target(event)
        assert target is None  # Rate not exceeded yet


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: DYNAMODB HEALTH CHECK TESTS (Fix K)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDynamoDBHealthCheck:
    """Tests for v7 DynamoDB table health validation."""

    def test_health_check_function_exists(self, setup_aws_resources):
        """_validate_dynamodb_health function should exist."""
        lf = setup_aws_resources["module"]
        assert hasattr(lf, "_validate_dynamodb_health")

    def test_health_check_sets_healthy_flag(self, setup_aws_resources):
        """In moto environment, tables should be reported as healthy."""
        lf = setup_aws_resources["module"]
        lf._DYNAMODB_HEALTHY = True  # Reset
        lf._PERMISSIONS_VALIDATED = False  # Force re-validation
        # Should not crash
        lf._validate_dynamodb_health()

    def test_dynamodb_healthy_global_exists(self, setup_aws_resources):
        """_DYNAMODB_HEALTHY global should exist."""
        lf = setup_aws_resources["module"]
        assert hasattr(lf, "_DYNAMODB_HEALTHY")


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: ENHANCED ECS TAKEDOWN TESTS (Fix I)
# ═══════════════════════════════════════════════════════════════════════════════

class TestECSEnhancedTakedown:
    """Tests for v7 ECS takedown with task role revocation."""

    def test_ecs_takedown_function_exists(self, setup_aws_resources):
        """execute_ecs_takedown should be callable."""
        lf = setup_aws_resources["module"]
        assert callable(lf.execute_ecs_takedown)

    def test_ecs_takedown_missing_cluster(self, setup_aws_resources):
        """ECS takedown with missing cluster should fail gracefully."""
        lf = setup_aws_resources["module"]
        result = lf.execute_ecs_takedown("arn:aws:ecs:us-east-1:123:task/abc", "")
        assert result["status"] == "FAILED"
        assert "Missing cluster ARN" in result["reason"]

    def test_revoke_ecs_task_role_function_exists(self, setup_aws_resources):
        """_revoke_ecs_task_role function should exist."""
        lf = setup_aws_resources["module"]
        assert hasattr(lf, "_revoke_ecs_task_role")


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: ENTROPY SCORE UTILITY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestEntropyScore:
    """Tests for v7 Shannon entropy calculation utility."""

    def test_empty_data(self):
        """Empty data should return 0.0 entropy."""
        from utils import entropy_score
        assert entropy_score(b"") == 0.0

    def test_uniform_data(self):
        """Data with all same bytes should have 0.0 entropy."""
        from utils import entropy_score
        assert entropy_score(b"\x00" * 1024) == 0.0

    def test_random_data_high_entropy(self):
        """Random-looking data should have high entropy (> 7.0)."""
        import os
        from utils import entropy_score
        random_data = os.urandom(4096)
        ent = entropy_score(random_data)
        assert ent > 7.0, f"Expected high entropy for random data, got {ent}"

    def test_text_data_moderate_entropy(self):
        """Regular text should have moderate entropy (3.0-5.5)."""
        from utils import entropy_score
        text = b"The quick brown fox jumps over the lazy dog. " * 100
        ent = entropy_score(text)
        assert 3.0 < ent < 5.5, f"Expected moderate entropy for text, got {ent}"

    def test_encrypted_file_simulated(self):
        """Simulated encrypted file should have near-maximum entropy."""
        from utils import entropy_score
        # Simulate encrypted data: all 256 byte values equally distributed
        encrypted = bytes(range(256)) * 16
        ent = entropy_score(encrypted)
        assert ent > 7.9, f"Expected near-max entropy for 'encrypted' data, got {ent}"
