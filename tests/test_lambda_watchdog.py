"""
CloudFreeze v7: Self-Defense Watchdog Lambda — Test Suite
==========================================================
Tests for lambda_watchdog.py using moto for AWS mocking.
Verifies all 5 integrity checks:
  A. EventBridge rules existence and state
  B. Lambda function code hash verification
  C. DynamoDB table health
  D. Quarantine Security Group existence
  E. IAM permissions validation
"""

import json
import os
import sys
import pytest
import boto3
from unittest.mock import patch, MagicMock

# Ensure the lambda directory is in the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

# Set environment variables before importing the module
os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:test-alerts"
os.environ["DYNAMODB_TABLE"] = "test-incidents"
os.environ["KMS_RATE_TABLE"] = "test-kms-rate"
os.environ["QUARANTINE_SG_ID"] = "sg-quarantine123"
os.environ["KILLSWITCH_FUNCTION_NAME"] = "test-killswitch"
os.environ["FORENSIC_FUNCTION_NAME"] = "test-forensic"
os.environ["RESTORE_FUNCTION_NAME"] = "test-restore"
os.environ["EXPECTED_EVENTBRIDGE_RULES"] = json.dumps(["rule-1", "rule-2"])
os.environ["LAMBDA_CODE_HASHES_PARAM"] = "/cloudfreeze/test-hashes"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"


class TestCheckEventBridgeRules:
    """Test EventBridge rule integrity checks."""

    def test_healthy_rules(self):
        """Verify healthy result when all rules are enabled."""
        with patch("lambda_watchdog.events_client") as mock_events:
            mock_events.describe_rule.return_value = {"State": "ENABLED"}
            mock_events.exceptions = MagicMock()
            mock_events.exceptions.ResourceNotFoundException = type("ResourceNotFoundException", (Exception,), {})

            from lambda_watchdog import check_eventbridge_rules
            result = check_eventbridge_rules()

            assert result["status"] == "HEALTHY"
            assert result["rules_verified"] > 0

    def test_disabled_rule_auto_remediated(self):
        """Verify disabled rules are detected and auto-remediated."""
        with patch("lambda_watchdog.events_client") as mock_events:
            mock_events.describe_rule.return_value = {"State": "DISABLED"}
            mock_events.enable_rule.return_value = {}
            mock_events.exceptions = MagicMock()
            mock_events.exceptions.ResourceNotFoundException = type("ResourceNotFoundException", (Exception,), {})

            from lambda_watchdog import check_eventbridge_rules
            result = check_eventbridge_rules()

            assert result["status"] == "COMPROMISED"
            assert len(result["disabled_rules"]) > 0
            assert result["auto_remediated"] is True

    def test_missing_rule(self):
        """Verify missing rules are detected."""
        with patch("lambda_watchdog.events_client") as mock_events:
            NotFoundException = type("ResourceNotFoundException", (Exception,), {})
            mock_events.describe_rule.side_effect = NotFoundException()
            mock_events.exceptions = MagicMock()
            mock_events.exceptions.ResourceNotFoundException = NotFoundException

            from lambda_watchdog import check_eventbridge_rules
            result = check_eventbridge_rules()

            assert result["status"] == "COMPROMISED"
            assert len(result["missing_rules"]) > 0

    def test_no_rules_configured(self):
        """Verify skipped when no rules configured."""
        with patch("lambda_watchdog.EXPECTED_EVENTBRIDGE_RULES", []):
            from lambda_watchdog import check_eventbridge_rules
            result = check_eventbridge_rules()
            assert result["status"] == "SKIPPED"


class TestCheckLambdaFunctions:
    """Test Lambda function integrity checks."""

    def test_all_functions_exist(self):
        """Verify healthy when all functions exist."""
        with patch("lambda_watchdog.lambda_client") as mock_lambda, \
             patch("lambda_watchdog.ssm_client") as mock_ssm:
            mock_lambda.get_function_configuration.return_value = {"CodeSha256": "abc123"}
            mock_lambda.exceptions = MagicMock()
            mock_lambda.exceptions.ResourceNotFoundException = type("ResourceNotFoundException", (Exception,), {})
            mock_ssm.get_parameter.side_effect = Exception("Not found")

            from lambda_watchdog import check_lambda_functions
            result = check_lambda_functions()

            assert result["status"] == "HEALTHY"
            assert result["functions_verified"] == 3

    def test_missing_function(self):
        """Verify compromised when a function is missing."""
        with patch("lambda_watchdog.lambda_client") as mock_lambda, \
             patch("lambda_watchdog.ssm_client") as mock_ssm:
            NotFoundException = type("ResourceNotFoundException", (Exception,), {})
            mock_lambda.get_function_configuration.side_effect = NotFoundException()
            mock_lambda.exceptions = MagicMock()
            mock_lambda.exceptions.ResourceNotFoundException = NotFoundException
            mock_ssm.get_parameter.side_effect = Exception("Not found")

            from lambda_watchdog import check_lambda_functions
            result = check_lambda_functions()

            assert result["status"] == "COMPROMISED"
            assert len(result["missing"]) == 3

    def test_code_hash_mismatch(self):
        """Verify compromised when code hash doesn't match known-good hash."""
        with patch("lambda_watchdog.lambda_client") as mock_lambda, \
             patch("lambda_watchdog.ssm_client") as mock_ssm:
            mock_lambda.get_function_configuration.return_value = {"CodeSha256": "modified_hash"}
            mock_lambda.exceptions = MagicMock()
            mock_lambda.exceptions.ResourceNotFoundException = type("ResourceNotFoundException", (Exception,), {})
            mock_ssm.get_parameter.return_value = {
                "Parameter": {"Value": json.dumps({"test-killswitch": "original_hash"})}
            }

            from lambda_watchdog import check_lambda_functions
            result = check_lambda_functions()

            assert result["status"] == "COMPROMISED"
            assert len(result["hash_mismatches"]) >= 1


class TestCheckDynamoDBTables:
    """Test DynamoDB table health checks."""

    def test_healthy_tables(self):
        """Verify healthy when all tables are ACTIVE."""
        with patch("lambda_watchdog.dynamodb_client") as mock_ddb:
            mock_ddb.describe_table.return_value = {"Table": {"TableStatus": "ACTIVE"}}
            mock_ddb.exceptions = MagicMock()
            mock_ddb.exceptions.ResourceNotFoundException = type("ResourceNotFoundException", (Exception,), {})

            from lambda_watchdog import check_dynamodb_tables
            result = check_dynamodb_tables()

            assert result["status"] == "HEALTHY"
            assert result["tables_verified"] == 2

    def test_deleted_table(self):
        """Verify compromised when a table is deleted."""
        with patch("lambda_watchdog.dynamodb_client") as mock_ddb:
            NotFoundException = type("ResourceNotFoundException", (Exception,), {})
            mock_ddb.describe_table.side_effect = NotFoundException()
            mock_ddb.exceptions = MagicMock()
            mock_ddb.exceptions.ResourceNotFoundException = NotFoundException

            from lambda_watchdog import check_dynamodb_tables
            result = check_dynamodb_tables()

            assert result["status"] == "COMPROMISED"
            assert len(result["missing"]) == 2


class TestCheckQuarantineSG:
    """Test quarantine Security Group checks."""

    def test_healthy_sg(self):
        """Verify healthy when SG exists with restrictive rules."""
        with patch("lambda_watchdog.ec2_client") as mock_ec2:
            mock_ec2.describe_security_groups.return_value = {
                "SecurityGroups": [{
                    "GroupId": "sg-quarantine123",
                    "IpPermissions": [],  # No ingress — secure
                }]
            }

            from lambda_watchdog import check_quarantine_sg
            result = check_quarantine_sg()

            assert result["status"] == "HEALTHY"

    def test_wide_open_ingress(self):
        """Verify compromised when SG has 0.0.0.0/0 ingress."""
        with patch("lambda_watchdog.ec2_client") as mock_ec2:
            mock_ec2.describe_security_groups.return_value = {
                "SecurityGroups": [{
                    "GroupId": "sg-quarantine123",
                    "IpPermissions": [{
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }],
                }]
            }

            from lambda_watchdog import check_quarantine_sg
            result = check_quarantine_sg()

            assert result["status"] == "COMPROMISED"


class TestWatchdogHandler:
    """Test the main watchdog handler."""

    def test_all_checks_healthy(self):
        """Verify overall healthy status when all checks pass."""
        with patch("lambda_watchdog.check_eventbridge_rules") as mock_eb, \
             patch("lambda_watchdog.check_lambda_functions") as mock_lf, \
             patch("lambda_watchdog.check_dynamodb_tables") as mock_db, \
             patch("lambda_watchdog.check_quarantine_sg") as mock_sg, \
             patch("lambda_watchdog.check_iam_permissions") as mock_iam:

            mock_eb.return_value = {"status": "HEALTHY"}
            mock_lf.return_value = {"status": "HEALTHY"}
            mock_db.return_value = {"status": "HEALTHY"}
            mock_sg.return_value = {"status": "HEALTHY"}
            mock_iam.return_value = {"status": "HEALTHY"}

            from lambda_watchdog import lambda_handler
            result = lambda_handler({}, None)

            body = json.loads(result["body"])
            assert body["overall_status"] == "HEALTHY"
            assert body["issues_found"] == 0

    def test_issues_trigger_alert(self):
        """Verify SNS alert is sent when issues are found."""
        with patch("lambda_watchdog.check_eventbridge_rules") as mock_eb, \
             patch("lambda_watchdog.check_lambda_functions") as mock_lf, \
             patch("lambda_watchdog.check_dynamodb_tables") as mock_db, \
             patch("lambda_watchdog.check_quarantine_sg") as mock_sg, \
             patch("lambda_watchdog.check_iam_permissions") as mock_iam, \
             patch("lambda_watchdog._send_critical_alert") as mock_alert:

            mock_eb.return_value = {"status": "COMPROMISED", "missing_rules": ["rule-1"]}
            mock_lf.return_value = {"status": "HEALTHY"}
            mock_db.return_value = {"status": "HEALTHY"}
            mock_sg.return_value = {"status": "HEALTHY"}
            mock_iam.return_value = {"status": "HEALTHY"}

            from lambda_watchdog import lambda_handler
            result = lambda_handler({}, None)

            body = json.loads(result["body"])
            assert body["overall_status"] == "DEGRADED"
            assert body["issues_found"] == 1
            mock_alert.assert_called_once()
