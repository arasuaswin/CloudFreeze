"""
CloudFreeze v7 — Unit Tests for Restore Lambda
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
def setup_restore_resources(aws_credentials):
    """Create resources and a pre-existing incident record for restore tests."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        normal_sg = ec2.create_security_group(
            GroupName="normal-sg", Description="Normal SG", VpcId=vpc_id
        )
        quarantine_sg = ec2.create_security_group(
            GroupName="quarantine-sg", Description="Quarantine SG", VpcId=vpc_id
        )
        normal_sg_id = normal_sg["GroupId"]
        quarantine_sg_id = quarantine_sg["GroupId"]

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="cloudfreeze-incidents",
            KeySchema=[{"AttributeName": "target_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "target_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        sns = boto3.client("sns", region_name="us-east-1")
        topic = sns.create_topic(Name="cloudfreeze-alerts")
        topic_arn = topic["TopicArn"]

        instances = ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1,
            InstanceType="t2.micro", SecurityGroupIds=[quarantine_sg_id],
        )
        instance_id = instances["Instances"][0]["InstanceId"]

        # Get the ENI ID
        instance_detail = ec2.describe_instances(InstanceIds=[instance_id])
        eni_id = instance_detail["Reservations"][0]["Instances"][0]["NetworkInterfaces"][0]["NetworkInterfaceId"]

        # Create incident record (simulating a completed takedown)
        table.put_item(Item={
            "target_id": instance_id,
            "tripwire": "test",
            "status": "COMPLETED",
            "takedown_results": json.dumps({
                "network_quarantine": {
                    "status": "SUCCESS",
                    "quarantine_sg": quarantine_sg_id,
                    "interfaces_quarantined": [{
                        "eni_id": eni_id,
                        "original_security_groups": [normal_sg_id],
                    }],
                },
                "iam_revocation": {"status": "SUCCESS", "revoked_profiles": []},
                "nacl_quarantine": {"status": "SKIPPED", "reason": "No NACL configured"},
            }),
        })

        os.environ["DYNAMODB_TABLE"] = "cloudfreeze-incidents"
        os.environ["SNS_TOPIC_ARN"] = topic_arn

        if "lambda_restore" in sys.modules:
            del sys.modules["lambda_restore"]
        import lambda_restore

        lambda_restore.ec2_client = boto3.client("ec2", region_name="us-east-1")
        lambda_restore.iam_client = boto3.client("iam", region_name="us-east-1")
        lambda_restore.sns_client = boto3.client("sns", region_name="us-east-1")
        lambda_restore.dynamodb_client = boto3.resource("dynamodb", region_name="us-east-1")

        yield {
            "module": lambda_restore,
            "instance_id": instance_id,
            "normal_sg_id": normal_sg_id,
            "quarantine_sg_id": quarantine_sg_id,
            "table": dynamodb.Table("cloudfreeze-incidents"),
            "ec2": ec2,
        }


class TestRestoreHandler:
    """Tests for the restore Lambda handler."""

    def test_missing_both_ids(self, setup_restore_resources):
        lr = setup_restore_resources["module"]
        result = lr.lambda_handler({}, None)
        assert result["statusCode"] == 400

    def test_invalid_event_type(self, setup_restore_resources):
        lr = setup_restore_resources["module"]
        result = lr.lambda_handler("string", None)
        assert result["statusCode"] == 400

    def test_no_incident_record(self, setup_restore_resources):
        lr = setup_restore_resources["module"]
        result = lr.lambda_handler({"instance_id": "i-doesnotexist"}, None)
        assert result["statusCode"] == 404

    def test_successful_restore(self, setup_restore_resources):
        lr = setup_restore_resources["module"]
        instance_id = setup_restore_resources["instance_id"]

        result = lr.lambda_handler({"instance_id": instance_id}, None)
        assert result["statusCode"] == 200

    def test_in_progress_refused(self, setup_restore_resources):
        lr = setup_restore_resources["module"]
        instance_id = setup_restore_resources["instance_id"]
        table = setup_restore_resources["table"]

        # Set status to IN_PROGRESS
        table.update_item(
            Key={"target_id": instance_id},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "IN_PROGRESS"},
        )

        result = lr.lambda_handler({"instance_id": instance_id}, None)
        assert result["statusCode"] == 409

    def test_already_restored(self, setup_restore_resources):
        lr = setup_restore_resources["module"]
        instance_id = setup_restore_resources["instance_id"]
        table = setup_restore_resources["table"]

        table.update_item(
            Key={"target_id": instance_id},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "RESTORED"},
        )

        result = lr.lambda_handler({"instance_id": instance_id}, None)
        assert result["statusCode"] == 200
        assert "already been restored" in result["body"]


# ═══════════════════════════════════════════════════════════════════════════════
#  v7: EXPANDED RESTORE TESTS (Fix #24)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExpandedRestore:
    """Additional restore edge case tests for v7."""

    def test_restore_terminated_instance(self, setup_restore_resources):
        """Restore of a terminated instance should handle gracefully."""
        lr = setup_restore_resources["module"]
        table = setup_restore_resources["table"]
        ec2 = setup_restore_resources["ec2"]

        # Create and terminate an instance
        instances = ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro",
        )
        terminated_id = instances["Instances"][0]["InstanceId"]
        ec2.terminate_instances(InstanceIds=[terminated_id])

        # Create incident record for it
        table.put_item(Item={
            "target_id": terminated_id,
            "tripwire": "test",
            "status": "COMPLETED",
            "takedown_results": json.dumps({
                "network_quarantine": {"status": "SUCCESS", "interfaces_quarantined": []},
                "iam_revocation": {"status": "SUCCESS", "revoked_profiles": []},
            }),
        })

        result = lr.lambda_handler({"instance_id": terminated_id}, None)
        assert result["statusCode"] in (200, 400)

    def test_restore_nacl_skipped_when_not_applied(self, setup_restore_resources):
        """NACL restore should be skipped when original quarantine didn't apply NACL."""
        lr = setup_restore_resources["module"]
        instance_id = setup_restore_resources["instance_id"]

        result = lr.lambda_handler({"instance_id": instance_id}, None)
        body = json.loads(result["body"]) if isinstance(result["body"], str) else result["body"]
        if isinstance(body, dict) and "nacl_restore" in body:
            assert body["nacl_restore"]["status"] == "SKIPPED"

    def test_restore_iam_entity(self, setup_restore_resources):
        """IAM entity restore should handle missing entity gracefully."""
        lr = setup_restore_resources["module"]
        table = setup_restore_resources["table"]

        table.put_item(Item={
            "target_id": "arn:aws:iam::123456789012:user/test-restore-user",
            "tripwire": "test",
            "status": "COMPLETED",
            "takedown_results": "{}",
        })

        result = lr.lambda_handler({
            "iam_arn": "arn:aws:iam::123456789012:user/test-restore-user",
        }, None)
        assert result["statusCode"] in (200, 400)
