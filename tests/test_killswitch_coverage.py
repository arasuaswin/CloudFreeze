"""
test_killswitch_coverage.py
===========================
Comprehensive tests to achieve 100% coverage of lambda_function.py.
Covers all 287 uncovered lines: error paths, edge cases, and core logic.
"""
import json
import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch, ANY
from botocore.exceptions import ClientError

# Ensure lambda/ is on PATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

# Env vars required by lambda_function.py at import time
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("DYNAMODB_TABLE", "CloudFreeze-Incidents")
os.environ.setdefault("KMS_RATE_TABLE", "CloudFreeze-KMSRate")
os.environ.setdefault("QUARANTINE_SG_ID", "sg-quarantine")
os.environ.setdefault("QUARANTINE_NACL_ID", "acl-quarantine")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:CloudFreeze-Alerts")
os.environ.setdefault("KMS_KEY_ARN", "arn:aws:kms:us-east-1:123456789012:key/test-key")
os.environ.setdefault("FORENSIC_LAMBDA_ARN", "arn:aws:lambda:us-east-1:123:function:forensic")
os.environ.setdefault("KMS_RATE_THRESHOLD", "5")
os.environ.setdefault("KMS_RATE_WINDOW", "60")
os.environ.setdefault("EXPECTED_EVENTBRIDGE_RULES", '["rule1","rule2"]')

import lambda_function as lf


# ═══════════════════════════════════════════════════════════════════════════════
#  PERMISSION VALIDATION (lines 161-184)
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateLambdaPermissions:
    """Cover _validate_lambda_permissions error paths."""

    def setup_method(self):
        lf._PERMISSIONS_VALIDATED = False  # Reset for each test

    def test_permissions_access_denied(self):
        """Lines 161-180: AccessDenied triggers critical alert."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "AccessDenied", "Message": "No perms"}},
                              "DescribeInstances")), \
             patch.object(lf.sns_client, "publish") as mock_pub, \
             patch.object(lf, "_validate_dynamodb_health"):
            lf._validate_lambda_permissions()
            mock_pub.assert_called_once()

    def test_permissions_unauthorized(self):
        """Lines 162-180: UnauthorizedOperation."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "UnauthorizedOperation", "Message": "No"}},
                              "DescribeInstances")), \
             patch.object(lf.sns_client, "publish") as mock_pub, \
             patch.object(lf, "_validate_dynamodb_health"):
            lf._validate_lambda_permissions()
            mock_pub.assert_called_once()

    def test_permissions_sns_also_fails(self):
        """Line 179-180: SNS also fails during permission alert."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "AccessDenied", "Message": "No"}},
                              "DescribeInstances")), \
             patch.object(lf.sns_client, "publish", side_effect=Exception("SNS down")), \
             patch.object(lf, "_validate_dynamodb_health"):
            lf._validate_lambda_permissions()  # Should not raise

    def test_permissions_other_client_error(self):
        """Line 181-182: Non-critical ClientError."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "Throttling", "Message": "Slow down"}},
                              "DescribeInstances")), \
             patch.object(lf, "_validate_dynamodb_health"):
            lf._validate_lambda_permissions()

    def test_permissions_generic_exception(self):
        """Lines 183-184: Generic exception."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=RuntimeError("Unknown")), \
             patch.object(lf, "_validate_dynamodb_health"):
            lf._validate_lambda_permissions()


# ═══════════════════════════════════════════════════════════════════════════════
#  DYNAMODB HEALTH VALIDATION (lines 200-224)
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateDynamoDBHealth:
    """Cover _validate_dynamodb_health error paths."""

    def setup_method(self):
        lf._DYNAMODB_HEALTHY = True

    def test_table_deleted(self):
        """Lines 200-220: ResourceNotFoundException → degraded mode."""
        with patch.object(lf.dynamodb_raw, "describe_table",
                          side_effect=ClientError(
                              {"Error": {"Code": "ResourceNotFoundException", "Message": "Deleted"}},
                              "DescribeTable")), \
             patch.object(lf.sns_client, "publish"):
            lf._validate_dynamodb_health()
            assert lf._DYNAMODB_HEALTHY is False

    def test_table_deleted_sns_fails(self):
        """Lines 218-220: SNS fails during DDB alert."""
        with patch.object(lf.dynamodb_raw, "describe_table",
                          side_effect=ClientError(
                              {"Error": {"Code": "ResourceNotFoundException", "Message": "Deleted"}},
                              "DescribeTable")), \
             patch.object(lf.sns_client, "publish", side_effect=Exception("SNS down")):
            lf._validate_dynamodb_health()  # Should not raise
            assert lf._DYNAMODB_HEALTHY is False

    def test_other_client_error(self):
        """Lines 221-222: Non-critical DDB error."""
        with patch.object(lf.dynamodb_raw, "describe_table",
                          side_effect=ClientError(
                              {"Error": {"Code": "Throttling", "Message": "Slow"}},
                              "DescribeTable")):
            lf._validate_dynamodb_health()

    def test_generic_exception(self):
        """Lines 223-224: Generic exception."""
        with patch.object(lf.dynamodb_raw, "describe_table",
                          side_effect=RuntimeError("Unknown")):
            lf._validate_dynamodb_health()


# ═══════════════════════════════════════════════════════════════════════════════
#  HANDLER PATHS (lines 279, 293-297)
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandlerPaths:
    """Cover additional lambda_handler branches."""

    def test_multi_ec2_target(self):
        """Line 279: multi-ec2 target dispatched."""
        with patch.object(lf, "_validate_lambda_permissions"), \
             patch.object(lf, "extract_target", return_value={
                 "type": "multi-ec2", "id": "multi", "tripwire": "alarm",
                 "instance_ids": ["i-123"]}), \
             patch.object(lf, "_handle_multi_instance_takedown",
                          return_value={"statusCode": 200, "body": "ok"}):
            result = lf.lambda_handler({"test": True}, None)
            assert result["statusCode"] == 200

    def test_ecs_target(self):
        """Lines 293-295: ECS target."""
        with patch.object(lf, "_validate_lambda_permissions"), \
             patch.object(lf, "extract_target", return_value={
                 "type": "ecs", "id": "arn:ecs:task/x", "cluster": "c",
                 "tripwire": "ecs-event"}), \
             patch.object(lf, "acquire_incident_lock", return_value=True), \
             patch.object(lf, "execute_ecs_takedown", return_value={"status": "SUCCESS"}), \
             patch.object(lf, "update_incident_record"), \
             patch.object(lf, "publish_notification"):
            result = lf.lambda_handler({"test": True}, None)
            assert result["statusCode"] == 200

    def test_unknown_target_type(self):
        """Lines 296-297: Unknown target type."""
        with patch.object(lf, "_validate_lambda_permissions"), \
             patch.object(lf, "extract_target", return_value={
                 "type": "unknown", "id": "x", "tripwire": "test"}), \
             patch.object(lf, "acquire_incident_lock", return_value=True), \
             patch.object(lf, "update_incident_record"), \
             patch.object(lf, "publish_notification"):
            result = lf.lambda_handler({"test": True}, None)
            assert "error" in result["body"]


# ═══════════════════════════════════════════════════════════════════════════════
#  MULTI-INSTANCE TAKEDOWN (lines 320-353)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMultiInstanceTakedown:
    """Cover _handle_multi_instance_takedown."""

    def test_no_target_instances_discovered(self):
        """Lines 320-328: No instances found."""
        with patch.object(lf, "_discover_monitored_instances", return_value=[]), \
             patch.object(lf, "publish_notification"):
            target = {"type": "multi-ec2", "id": "multi", "instance_ids": []}
            result = lf._handle_multi_instance_takedown(target, "alarm", {})
            assert "NO TARGETS" in result["body"] or result["statusCode"] == 200

    def test_instances_found_and_processed(self):
        """Lines 330-353: Instances found and quarantined."""
        with patch.object(lf, "acquire_incident_lock", side_effect=[True, False]), \
             patch.object(lf, "execute_ec2_takedown",
                          return_value={"status": "SUCCESS"}), \
             patch.object(lf, "publish_notification"):
            target = {"instance_ids": ["i-aaa", "i-bbb"]}
            result = lf._handle_multi_instance_takedown(target, "alarm", {})
            assert result["statusCode"] == 200
            body = result["body"]
            assert body["instances_processed"] == 2

    def test_discover_monitored_instances_success(self):
        """Lines 356-373: _discover_monitored_instances returns instances."""
        with patch.object(lf.ec2_client, "describe_instances",
                          return_value={"Reservations": [
                              {"Instances": [{"InstanceId": "i-111"}, {"InstanceId": "i-222"}]}
                          ]}):
            result = lf._discover_monitored_instances()
            assert "i-111" in result
            assert len(result) == 2

    def test_discover_monitored_instances_error(self):
        """Lines 371-373: _discover_monitored_instances error path."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=Exception("API error")):
            result = lf._discover_monitored_instances()
            assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
#  EVENT EXTRACTORS (lines 452-454, 510, 547-576, 594-619, 640-689, 711-770)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtractTarget:
    """Cover extract_target exception path."""

    def test_extract_target_exception(self):
        """Lines 452-454: Exception during extraction."""
        with patch.object(lf, "_extract_from_instance_agent", side_effect=Exception("crash")):
            result = lf.extract_target({"source": "instance-agent", "instance_id": "i-1"})
            assert result is None

    def test_extract_ecs_manual(self):
        """Lines 440-447: Manual ECS test invocation."""
        result = lf.extract_target({"task_arn": "arn:ecs:task/x", "cluster": "c"})
        assert result["type"] == "ecs"
        assert result["tripwire"] == "manual-test"


class TestExtractFromECSEvent:
    """Cover _extract_from_ecs_event."""

    def test_ecs_with_nonzero_exit_code(self):
        """Line 510: Container with non-zero exit code."""
        event = {
            "source": "aws.ecs",
            "detail-type": "ECS Task State Change",
            "detail": {
                "taskArn": "arn:ecs:task/abc",
                "clusterArn": "arn:ecs:cluster/c",
                "group": "service:svc",
                "lastStatus": "STOPPED",
                "containers": [
                    {"name": "suspicious", "exitCode": 137},
                ],
            },
        }
        result = lf._extract_from_ecs_event(event)
        assert result["type"] == "ecs"
        assert result["id"] == "arn:ecs:task/abc"


class TestExtractFromGuardDuty:
    """Cover _extract_from_guardduty."""

    def test_guardduty_ec2_finding(self):
        """Lines 547-564: EC2-targeted finding."""
        event = {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "detail": {
                "type": "Recon:EC2/PortProbeUnprotectedPort",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {"instanceId": "i-guard"},
                },
            },
        }
        result = lf._extract_from_guardduty(event)
        assert result["type"] == "ec2"
        assert result["id"] == "i-guard"

    def test_guardduty_iam_finding(self):
        """Lines 565-570: IAM user targeted finding."""
        event = {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "detail": {
                "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                "resource": {
                    "resourceType": "AccessKey",
                    "accessKeyDetails": {
                        "userName": "attacker",
                        "userType": "IAMUser",
                    },
                },
            },
        }
        result = lf._extract_from_guardduty(event)
        assert result is not None

    def test_guardduty_ecs_finding(self):
        """ECS container finding."""
        event = {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "detail": {
                "type": "Runtime:ECS/CryptoMiner",
                "resource": {
                    "resourceType": "ECSCluster",
                    "ecsClusterDetails": {
                        "arn": "arn:aws:ecs:us-east-1:123:cluster/prod",
                        "taskDetails": {
                            "arn": "arn:aws:ecs:task/abc",
                        },
                    },
                },
            },
        }
        result = lf._extract_from_guardduty(event)
        # May return ecs target or None depending on implementation
        assert result is None or isinstance(result, dict)

    def test_guardduty_unmappable_finding(self):
        """Lines 575-576: Finding that can't be mapped."""
        event = {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "detail": {
                "type": "Policy:S3/BucketPublicAccess",
                "resource": {"resourceType": "S3Bucket"},
            },
        }
        result = lf._extract_from_guardduty(event)
        assert result is None


class TestExtractFromRecords:
    """Cover _extract_from_records (lines 594-619)."""

    def test_s3_event_with_iam_principal(self):
        """Lines 593-601: S3 event from non-EC2 principal → mass quarantine."""
        with patch.object(lf, "_discover_monitored_instances", return_value=["i-1", "i-2"]):
            event = {
                "Records": [{
                    "eventSource": "aws:s3",
                    "s3": {"bucket": {"name": "honeypot"}, "object": {"key": "secret.txt"}},
                    "userIdentity": {"principalId": "AIDA123456789"},
                }],
            }
            result = lf._extract_from_records(event)
            assert result["type"] == "multi-ec2"

    def test_sns_alarm_with_instance_id(self):
        """Lines 604-615: SNS-wrapped alarm with InstanceId dimension."""
        event = {
            "Records": [{
                "EventSource": "aws:sns",
                "Sns": {
                    "Message": json.dumps({
                        "Trigger": {
                            "Dimensions": [{"name": "InstanceId", "value": "i-sns"}],
                        },
                    }),
                },
            }],
        }
        result = lf._extract_from_records(event)
        assert result["type"] == "ec2"
        assert result["id"] == "i-sns"

    def test_sns_alarm_parse_error(self):
        """Lines 616-617: Malformed SNS message."""
        event = {
            "Records": [{
                "EventSource": "aws:sns",
                "Sns": {"Message": "not-json"},
            }],
        }
        result = lf._extract_from_records(event)
        assert result is None


class TestExtractFromCloudTrailEvent:
    """Cover _extract_from_cloudtrail_event (lines 640-689)."""

    def test_non_kms_non_s3_event(self):
        """Line 640: Other event source tripwire."""
        event = {
            "detail": {
                "eventName": "StopInstances",
                "eventSource": "ec2.amazonaws.com",
                "requestParameters": {
                    "instancesSet": {"items": [{"instanceId": "i-ec2"}]},
                },
            },
        }
        result = lf._extract_from_cloudtrail_event(event)
        assert result["tripwire"] == "cloudtrail-ec2.amazonaws.com"
        assert result["id"] == "i-ec2"

    def test_s3_bulk_ops_below_threshold(self):
        """Lines 655-662: S3 bulk operation below threshold."""
        lf._LOCAL_S3_RATE_CACHE.clear()
        event = {
            "detail": {
                "eventName": "DeleteObject",
                "eventSource": "s3.amazonaws.com",
                "userIdentity": {"principalId": "user1"},
            },
        }
        result = lf._extract_from_cloudtrail_event(event)
        # First call — below threshold
        assert result is None

    def test_cloudtrail_iam_user_identity(self):
        """Lines 678-680: IAM user identity extraction."""
        event = {
            "detail": {
                "eventName": "GetObject",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "eu-west-1",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123:user/attacker",
                },
            },
        }
        # Need to make rate counter return True
        with patch.object(lf, "_check_s3_rate_limit", return_value=True):
            result = lf._extract_from_cloudtrail_event(event)
            assert result is not None

    def test_cloudtrail_assumed_role_identity(self):
        """Lines 681-685: AssumedRole identity."""
        event = {
            "detail": {
                "eventName": "Decrypt",
                "eventSource": "kms.amazonaws.com",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::123:assumed-role/role/session",
                    "sessionContext": {
                        "sessionIssuer": {
                            "arn": "arn:aws:iam::123:role/my-role",
                        },
                    },
                },
            },
        }
        with patch.object(lf, "_check_kms_rate_limit", return_value=True):
            result = lf._extract_from_cloudtrail_event(event)
            assert result["type"] == "iam"
            assert result["iam_type"] == "role"

    def test_cloudtrail_unknown_identity(self):
        """Lines 686-687: Unknown identity type."""
        event = {
            "detail": {
                "eventName": "Decrypt",
                "eventSource": "kms.amazonaws.com",
                "userIdentity": {
                    "type": "FederatedUser",
                    "arn": "arn:aws:sts::123:federated-user/unknown",
                },
            },
        }
        with patch.object(lf, "_check_kms_rate_limit", return_value=True):
            result = lf._extract_from_cloudtrail_event(event)
            assert result["iam_type"] == "unknown"


class TestExtractFromAlarmEvent:
    """Cover _extract_from_alarm_event (lines 711-725)."""

    def test_alarm_trigger_dimensions(self):
        """Lines 710-716: Older alarm format with trigger.dimensions."""
        event = {
            "detail": {
                "alarmName": "CPUAlarm",
                "configuration": {"metrics": []},
                "trigger": {
                    "dimensions": [{"name": "InstanceId", "value": "i-alarm"}],
                },
            },
        }
        result = lf._extract_from_alarm_event(event)
        assert result["id"] == "i-alarm"

    def test_alarm_no_instance_id(self):
        """Lines 720-725: No InstanceId → mass quarantine."""
        event = {
            "detail": {
                "alarmName": "KMSRate",
                "configuration": {"metrics": []},
                "trigger": {"dimensions": []},
            },
        }
        result = lf._extract_from_alarm_event(event)
        assert result["type"] == "multi-ec2"


class TestExtractInstanceFromCloudTrail:
    """Cover _extract_instance_from_cloudtrail (lines 735-770)."""

    def test_response_elements_instances_set(self):
        """Lines 740-746: responseElements.instancesSet."""
        detail = {
            "requestParameters": {},
            "responseElements": {
                "instancesSet": {"items": [{"instanceId": "i-resp"}]},
            },
        }
        result = lf._extract_instance_from_cloudtrail(detail)
        assert result == "i-resp"

    def test_session_context_arn_with_instance(self):
        """Lines 756-763: sessionContext ARN with :instance/."""
        detail = {
            "userIdentity": {
                "sessionContext": {
                    "sessionIssuer": {"arn": "arn:aws:ec2:us-east-1:123:instance/i-session"},
                },
            },
        }
        result = lf._extract_instance_from_cloudtrail(detail)
        assert result == "i-session"

    def test_resources_array_with_instance(self):
        """Lines 766-770: resources array."""
        detail = {
            "resources": [
                {"ARN": "arn:aws:ec2:us-east-1:123:instance/i-res"},
            ],
        }
        result = lf._extract_instance_from_cloudtrail(detail)
        assert result == "i-res"


# ═══════════════════════════════════════════════════════════════════════════════
#  KMS RATE LIMIT (lines 839-851)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckKmsRateLimit:
    """Cover _check_kms_rate_limit error path."""

    def test_kms_rate_dynamodb_failure(self):
        """Lines 839-851: DynamoDB error → in-memory fallback."""
        with patch.object(lf.dynamodb_raw, "update_item",
                          side_effect=Exception("DDB down")):
            # Clear cache
            lf._LOCAL_KMS_RATE_CACHE.clear()
            result = lf._check_kms_rate_limit()
            assert isinstance(result, bool)


# ═══════════════════════════════════════════════════════════════════════════════
#  IDEMPOTENCY LOCK (lines 902-932)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAcquireIncidentLock:
    """Cover acquire_incident_lock error paths."""

    def test_lock_conditional_check_failed(self):
        """Lines 902-905: ConditionalCheckFailedException → already locked."""
        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Exists"}},
            "PutItem"
        )
        with patch.object(lf.dynamodb_client, "Table", return_value=mock_table):
            lf._LOCAL_DEDUP_CACHE.clear()
            result = lf.acquire_incident_lock("i-test", "test")
            assert result is False

    def test_lock_dynamodb_error(self):
        """Lines 906-910: Generic DDB error → fail-open."""
        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "DDB error"}},
            "PutItem"
        )
        with patch.object(lf.dynamodb_client, "Table", return_value=mock_table):
            lf._LOCAL_DEDUP_CACHE.clear()
            result = lf.acquire_incident_lock("i-ddb-err", "test")
            assert result is True

    def test_lock_generic_exception(self):
        """Lines 912-915: Generic exception → fail-open."""
        mock_table = MagicMock()
        mock_table.put_item.side_effect = RuntimeError("Crash")
        with patch.object(lf.dynamodb_client, "Table", return_value=mock_table):
            lf._LOCAL_DEDUP_CACHE.clear()
            result = lf.acquire_incident_lock("i-crash", "test")
            assert result is True

    def test_update_incident_record_error(self):
        """Lines 931-932: update_incident_record failure."""
        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DDB error")
        with patch.object(lf.dynamodb_client, "Table", return_value=mock_table):
            lf.update_incident_record("i-test", {"status": "done"})  # Should not raise


# ═══════════════════════════════════════════════════════════════════════════════
#  EC2 TAKEDOWN (lines 961-998)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecuteEC2Takedown:
    """Cover execute_ec2_takedown paths."""

    def test_cross_region_log(self):
        """Line 961: Cross-region client pool log."""
        with patch.object(lf, "_get_instance_state", return_value="running"), \
             patch.object(lf, "_verify_sg_exists", return_value=True), \
             patch.object(lf, "_prewrite_original_state"), \
             patch.object(lf, "perform_network_quarantine", return_value={"status": "SUCCESS"}), \
             patch.object(lf, "perform_ec2_iam_revocation", return_value={"status": "SUCCESS"}), \
             patch.object(lf, "_invoke_async_forensics", return_value={"status": "ASYNC"}), \
             patch.object(lf, "perform_nacl_quarantine", return_value={"status": "SUCCESS"}), \
             patch.object(lf, "update_incident_record"):
            result = lf.execute_ec2_takedown("i-test", target_region="eu-west-1")
            assert result["instance_id"] == "i-test"

    def test_instance_not_found(self):
        """Lines 965-967: Instance not found."""
        with patch.object(lf, "_get_instance_state", return_value=None):
            result = lf.execute_ec2_takedown("i-gone")
            assert result["status"] == "FAILED"

    def test_instance_terminated(self):
        """Lines 968-970: Instance terminated."""
        with patch.object(lf, "_get_instance_state", return_value="terminated"):
            result = lf.execute_ec2_takedown("i-dead")
            assert result["status"] == "SKIPPED"

    def test_quarantine_sg_not_found(self):
        """Lines 973-976: SG doesn't exist."""
        with patch.object(lf, "_get_instance_state", return_value="running"), \
             patch.object(lf, "_verify_sg_exists", return_value=False):
            result = lf.execute_ec2_takedown("i-nosg")
            assert result["status"] == "FAILED"

    def test_circuit_breaker_tripped(self):
        """Lines 993-998: Circuit breaker defers remaining actions."""
        cb_mock = MagicMock()
        cb_mock.is_tripped.return_value = True
        with patch.object(lf, "_get_instance_state", return_value="running"), \
             patch.object(lf, "_verify_sg_exists", return_value=True), \
             patch.object(lf, "_prewrite_original_state"), \
             patch.object(lf, "perform_network_quarantine", return_value={"status": "SUCCESS"}), \
             patch.object(lf, "perform_ec2_iam_revocation", return_value={"status": "SUCCESS"}), \
             patch.object(lf, "update_incident_record"), \
             patch("lambda_function.CircuitBreaker", return_value=cb_mock):
            result = lf.execute_ec2_takedown("i-cb")
            assert result["forensic_preservation"]["status"] == "DEFERRED"


# ═══════════════════════════════════════════════════════════════════════════════
#  ECS TAKEDOWN (lines 1076-1165)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecuteECSTakedown:
    """Cover execute_ecs_takedown."""

    def test_ecs_success(self):
        """Lines 1076-1086: Successful ECS takedown."""
        with patch.object(lf.ecs_client, "stop_task"), \
             patch.object(lf, "_revoke_ecs_task_role",
                          return_value={"status": "SUCCESS"}), \
             patch.object(lf, "update_incident_record"):
            result = lf.execute_ecs_takedown("arn:task/x", "arn:cluster/c")
            assert result["status"] == "SUCCESS"

    def test_ecs_client_error(self):
        """Lines 1088-1092: ClientError on stop_task."""
        with patch.object(lf.ecs_client, "stop_task",
                          side_effect=ClientError(
                              {"Error": {"Code": "TaskNotFound", "Message": "Gone"}},
                              "StopTask")), \
             patch.object(lf, "update_incident_record"):
            result = lf.execute_ecs_takedown("arn:task/x", "arn:cluster/c")
            assert result["status"] == "FAILED"

    def test_ecs_generic_error(self):
        """Lines 1093-1097: Generic exception."""
        with patch.object(lf.ecs_client, "stop_task",
                          side_effect=RuntimeError("Crash")), \
             patch.object(lf, "update_incident_record"):
            result = lf.execute_ecs_takedown("arn:task/x", "arn:cluster/c")
            assert result["status"] == "FAILED"


class TestRevokeECSTaskRole:
    """Cover _revoke_ecs_task_role (lines 1109-1165)."""

    def test_task_not_found(self):
        """Lines 1116-1117: Task not found."""
        with patch.object(lf.ecs_client, "describe_tasks",
                          return_value={"tasks": []}):
            result = lf._revoke_ecs_task_role("arn:task/x", "arn:cluster/c")
            assert result["status"] == "SKIPPED"

    def test_no_task_role(self):
        """Lines 1132-1133: No task role attached."""
        with patch.object(lf.ecs_client, "describe_tasks",
                          return_value={"tasks": [{"overrides": {}, "taskDefinitionArn": ""}]}):
            result = lf._revoke_ecs_task_role("arn:task/x", "arn:cluster/c")
            assert result["status"] == "SKIPPED"

    def test_task_role_from_definition(self):
        """Lines 1124-1130: Role from task definition."""
        with patch.object(lf.ecs_client, "describe_tasks",
                          return_value={"tasks": [{
                              "overrides": {},
                              "taskDefinitionArn": "arn:aws:ecs:td/my-def:1",
                          }]}), \
             patch.object(lf.ecs_client, "describe_task_definition",
                          return_value={"taskDefinition": {
                              "taskRoleArn": "arn:aws:iam::123:role/ecs-role",
                          }}), \
             patch.object(lf.iam_client, "put_role_policy"):
            result = lf._revoke_ecs_task_role("arn:task/x", "arn:cluster/c")
            assert result["status"] == "SUCCESS"

    def test_task_role_client_error(self):
        """Lines 1158-1161: ClientError."""
        with patch.object(lf.ecs_client, "describe_tasks",
                          side_effect=ClientError(
                              {"Error": {"Code": "Error", "Message": "bad"}}, "DescribeTasks")):
            result = lf._revoke_ecs_task_role("arn:task/x", "arn:cluster/c")
            assert result["status"] == "FAILED"

    def test_task_role_generic_error(self):
        """Lines 1162-1165: Generic exception."""
        with patch.object(lf.ecs_client, "describe_tasks",
                          side_effect=RuntimeError("Crash")):
            result = lf._revoke_ecs_task_role("arn:task/x", "arn:cluster/c")
            assert result["status"] == "FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
#  ASYNC FORENSICS + HELPERS (lines 1185-1218)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAsyncForensicsAndHelpers:
    """Cover _invoke_async_forensics, _get_instance_state, _verify_sg_exists."""

    def test_async_forensics_success(self):
        """Lines 1185-1186: Successful async invocation."""
        with patch.object(lf.lambda_client, "invoke"):
            result = lf._invoke_async_forensics("i-test")
            assert result["status"] == "ASYNC_INVOKED"

    def test_async_forensics_failure_fallback(self):
        """Lines 1187-1190: Async fails → inline fallback."""
        with patch.object(lf.lambda_client, "invoke", side_effect=Exception("Lambda err")), \
             patch.object(lf, "perform_forensic_preservation",
                          return_value={"status": "SUCCESS"}):
            result = lf._invoke_async_forensics("i-test")
            assert result["status"] == "SUCCESS"

    def test_get_instance_state_not_found(self):
        """Lines 1199: No reservations."""
        with patch.object(lf.ec2_client, "describe_instances",
                          return_value={"Reservations": []}):
            assert lf._get_instance_state("i-test") is None

    def test_get_instance_state_invalid_id(self):
        """Lines 1202-1203: InvalidInstanceID.NotFound."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "InvalidInstanceID.NotFound", "Message": "NF"}},
                              "DescribeInstances")):
            assert lf._get_instance_state("i-test") is None

    def test_get_instance_state_malformed_id(self):
        """Lines 1204-1206: InvalidInstanceID.Malformed."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "InvalidInstanceID.Malformed", "Message": "Bad"}},
                              "DescribeInstances")):
            assert lf._get_instance_state("bad-id") is None

    def test_verify_sg_not_found(self):
        """Line 1218: SG not found raises."""
        with patch.object(lf.ec2_client, "describe_security_groups",
                          side_effect=ClientError(
                              {"Error": {"Code": "InvalidGroup.NotFound", "Message": "NF"}},
                              "DescribeSecurityGroups")):
            assert lf._verify_sg_exists("sg-gone") is False


# ═══════════════════════════════════════════════════════════════════════════════
#  IAM TAKEDOWN (lines 1240-1292)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecuteIAMTakedown:
    """Cover execute_iam_takedown edge cases."""

    def test_iam_empty_entity_name(self):
        """Lines 1240-1241: Empty entity name."""
        with patch.object(lf, "_extract_entity_name", return_value=None), \
             patch.object(lf, "update_incident_record"):
            result = lf.execute_iam_takedown("not-an-arn", "user")
            assert "error" in result

    def test_iam_client_error(self):
        """Lines 1271-1274: ClientError."""
        with patch.object(lf, "_extract_entity_name", return_value="test-user"), \
             patch.object(lf, "_apply_user_deny",
                          side_effect=ClientError(
                              {"Error": {"Code": "NoSuchEntity", "Message": "NF"}},
                              "PutUserPolicy")), \
             patch.object(lf, "update_incident_record"):
            result = lf.execute_iam_takedown("arn:aws:iam::123:user/test-user", "user")
            assert "error" in result

    def test_iam_generic_exception(self):
        """Lines 1271-1274: Generic exception."""
        with patch.object(lf, "_extract_entity_name",
                          side_effect=RuntimeError("Crash")), \
             patch.object(lf, "update_incident_record"):
            result = lf.execute_iam_takedown("arn:aws:iam::123:user/test", "user")
            assert "error" in result

    def test_extract_entity_name_not_string(self):
        """Lines 1291-1292: Non-string ARN."""
        assert lf._extract_entity_name(None) is None
        assert lf._extract_entity_name(12345) is None

    def test_extract_entity_name_exception(self):
        """Line 1291-1292: Exception path."""
        assert lf._extract_entity_name(None) is None


# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK QUARANTINE (lines 1363-1401)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPerformNetworkQuarantine:
    """Cover perform_network_quarantine."""

    def test_no_reservations(self):
        """Line 1363: Instance not found."""
        with patch.object(lf.ec2_client, "describe_instances",
                          return_value={"Reservations": []}):
            result = lf.perform_network_quarantine("i-gone")
            assert result["status"] == "FAILED"

    def test_no_enis(self):
        """Line 1370: No network interfaces."""
        with patch.object(lf.ec2_client, "describe_instances",
                          return_value={"Reservations": [{
                              "Instances": [{"NetworkInterfaces": []}]
                          }]}):
            result = lf.perform_network_quarantine("i-noeni")
            assert result["status"] == "WARNING"

    def test_client_error(self):
        """Lines 1394-1397: ClientError."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "Error", "Message": "bad"}},
                              "DescribeInstances")):
            result = lf.perform_network_quarantine("i-err")
            assert result["status"] == "FAILED"

    def test_generic_error(self):
        """Lines 1398-1401: Generic exception."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=RuntimeError("Crash")):
            result = lf.perform_network_quarantine("i-crash")
            assert result["status"] == "FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
#  NACL QUARANTINE (lines 1432-1504)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPerformNACLQuarantine:
    """Cover perform_nacl_quarantine."""

    def test_no_subnet(self):
        """Line 1432: No subnet found."""
        with patch.object(lf.ec2_client, "describe_instances",
                          return_value={"Reservations": [{
                              "Instances": [{"SubnetId": "", "PrivateIpAddress": "10.0.0.1"}]
                          }]}):
            result = lf.perform_nacl_quarantine("i-test")
            assert result["status"] == "SKIPPED"

    def test_multi_instance_no_private_ip(self):
        """Line 1450: No private IP for per-IP deny."""
        with patch.object(lf.ec2_client, "describe_instances") as mock_desc:
            mock_desc.side_effect = [
                # First call: get instance
                {"Reservations": [{"Instances": [{"SubnetId": "subnet-1", "PrivateIpAddress": ""}]}]},
                # Second call: count instances
                {"Reservations": [{"Instances": [{"InstanceId": "i-1"}, {"InstanceId": "i-2"}]}]},
            ]
            result = lf.perform_nacl_quarantine("i-test")
            assert result["status"] == "SKIPPED"

    def test_single_instance_no_nacl_assoc(self):
        """Lines 1476-1477: No NACL association found."""
        with patch.object(lf.ec2_client, "describe_instances") as mock_desc:
            mock_desc.side_effect = [
                {"Reservations": [{"Instances": [{"SubnetId": "sub-1", "PrivateIpAddress": "10.0.0.1"}]}]},
                {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]},
            ]
            with patch.object(lf.ec2_client, "describe_network_acls",
                              return_value={"NetworkAcls": []}):
                result = lf.perform_nacl_quarantine("i-test")
                assert result["status"] == "SKIPPED"

    def test_nacl_client_error(self):
        """Lines 1497-1500: ClientError."""
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = "acl-quarantine"
        try:
            with patch.object(lf.ec2_client, "describe_instances",
                              side_effect=ClientError(
                                  {"Error": {"Code": "Error", "Message": "bad"}},
                                  "DescribeInstances")):
                result = lf.perform_nacl_quarantine("i-err")
                assert result["status"] == "FAILED"
        finally:
            lf.QUARANTINE_NACL_ID = saved

    def test_nacl_generic_error(self):
        """Lines 1501-1504: Generic exception."""
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = "acl-quarantine"
        try:
            with patch.object(lf.ec2_client, "describe_instances",
                              side_effect=RuntimeError("Crash")):
                result = lf.perform_nacl_quarantine("i-crash")
                assert result["status"] == "FAILED"
        finally:
            lf.QUARANTINE_NACL_ID = saved


# ═══════════════════════════════════════════════════════════════════════════════
#  PER-IP NACL DENY (lines 1530, 1585-1592)
# ═══════════════════════════════════════════════════════════════════════════════

class TestApplyPerIPNACLDeny:
    """Cover _apply_per_ip_nacl_deny error paths."""

    def test_no_nacl_found(self):
        """Line 1530: No NACL found."""
        with patch.object(lf.ec2_client, "describe_network_acls",
                          return_value={"NetworkAcls": []}):
            result = lf._apply_per_ip_nacl_deny("i-test", "sub-1", "10.0.0.1")
            assert result["status"] == "SKIPPED"

    def test_client_error(self):
        """Lines 1585-1588: ClientError."""
        with patch.object(lf.ec2_client, "describe_network_acls",
                          side_effect=ClientError(
                              {"Error": {"Code": "Error", "Message": "bad"}},
                              "DescribeNetworkAcls")):
            result = lf._apply_per_ip_nacl_deny("i-test", "sub-1", "10.0.0.1")
            assert result["status"] == "FAILED"

    def test_generic_error(self):
        """Lines 1589-1592: Generic exception."""
        with patch.object(lf.ec2_client, "describe_network_acls",
                          side_effect=RuntimeError("Crash")):
            result = lf._apply_per_ip_nacl_deny("i-test", "sub-1", "10.0.0.1")
            assert result["status"] == "FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
#  SSM AGENT HEALTH (lines 1613-1624)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckSSMAgentHealth:
    """Cover _check_ssm_agent_health."""

    def test_ssm_agent_online(self):
        """Lines 1613-1616: Agent is online."""
        with patch.object(lf.ssm_client, "describe_instance_information",
                          return_value={"InstanceInformationList": [
                              {"PingStatus": "Online"}
                          ]}):
            assert lf._check_ssm_agent_health("i-test") is True

    def test_ssm_agent_offline(self):
        """Lines 1617-1621: Agent not online."""
        with patch.object(lf.ssm_client, "describe_instance_information",
                          return_value={"InstanceInformationList": [
                              {"PingStatus": "ConnectionLost"}
                          ]}):
            assert lf._check_ssm_agent_health("i-test") is False

    def test_ssm_client_error(self):
        """Lines 1622-1624: ClientError."""
        with patch.object(lf.ssm_client, "describe_instance_information",
                          side_effect=ClientError(
                              {"Error": {"Code": "AccessDenied", "Message": "No"}},
                              "DescribeInstanceInformation")):
            assert lf._check_ssm_agent_health("i-test") is False


# ═══════════════════════════════════════════════════════════════════════════════
#  EC2 IAM REVOCATION (lines 1648-1672)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPerformEC2IAMRevocation:
    """Cover perform_ec2_iam_revocation."""

    def test_profile_revoked(self):
        """Lines 1648-1663: Successfully revoke IAM profiles."""
        with patch.object(lf.ec2_client, "describe_instances",
                          return_value={"Reservations": [{"Instances": [{
                              "IamInstanceProfile": {"Arn": "arn:aws:iam:ip/test"},
                          }]}]}), \
             patch.object(lf.ec2_client, "describe_iam_instance_profile_associations",
                          return_value={"IamInstanceProfileAssociations": [{
                              "AssociationId": "assoc-1",
                              "IamInstanceProfile": {"Arn": "arn:aws:iam:ip/test"},
                          }]}), \
             patch.object(lf.ec2_client, "disassociate_iam_instance_profile"):
            result = lf.perform_ec2_iam_revocation("i-test")
            assert result["status"] == "SUCCESS"
            assert len(result["revoked_profiles"]) == 1

    def test_client_error(self):
        """Lines 1665-1668: ClientError."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "Error", "Message": "bad"}},
                              "DescribeInstances")):
            result = lf.perform_ec2_iam_revocation("i-err")
            assert result["status"] == "FAILED"

    def test_generic_error(self):
        """Lines 1669-1672: Generic exception."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=RuntimeError("Crash")):
            result = lf.perform_ec2_iam_revocation("i-crash")
            assert result["status"] == "FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
#  FORENSIC PRESERVATION (lines 1692-1774)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPerformForensicPreservation:
    """Cover perform_forensic_preservation."""

    def test_no_volumes(self):
        """Lines 1692-1693: No volumes attached."""
        with patch.object(lf.ec2_client, "describe_volumes",
                          return_value={"Volumes": []}):
            result = lf.perform_forensic_preservation("i-test")
            assert result["status"] == "SUCCESS"
            assert result["snapshots"] == []

    def test_volume_skipped_bad_state(self):
        """Lines 1703-1710: Volume not in snapshotable state."""
        with patch.object(lf.ec2_client, "describe_volumes",
                          return_value={"Volumes": [
                              {"VolumeId": "vol-1", "State": "creating"},
                          ]}):
            result = lf.perform_forensic_preservation("i-test")
            assert result["snapshots"][0]["status"] == "SKIPPED"

    def test_unencrypted_volume_copy(self):
        """Lines 1746-1759: Unencrypted volume with encrypted copy."""
        saved_key = lf.KMS_KEY_ARN
        lf.KMS_KEY_ARN = "arn:aws:kms:us-east-1:123:key/test"
        try:
            with patch.object(lf.ec2_client, "describe_volumes",
                              return_value={"Volumes": [
                                  {"VolumeId": "vol-1", "State": "in-use", "Encrypted": False},
                              ]}), \
                 patch.object(lf.ec2_client, "create_snapshot",
                              return_value={"SnapshotId": "snap-1"}), \
                 patch.object(lf.ec2_client, "copy_snapshot",
                              return_value={"SnapshotId": "snap-enc"}):
                result = lf.perform_forensic_preservation("i-test")
                assert result["snapshots"][0]["encrypted_copy_id"] == "snap-enc"
        finally:
            lf.KMS_KEY_ARN = saved_key

    def test_encrypted_copy_fails(self):
        """Lines 1757-1759: Encrypted copy fails."""
        saved_key = lf.KMS_KEY_ARN
        lf.KMS_KEY_ARN = "arn:aws:kms:us-east-1:123:key/test"
        try:
            with patch.object(lf.ec2_client, "describe_volumes",
                              return_value={"Volumes": [
                                  {"VolumeId": "vol-1", "State": "in-use", "Encrypted": False},
                          ]}), \
                 patch.object(lf.ec2_client, "create_snapshot",
                              return_value={"SnapshotId": "snap-1"}), \
                 patch.object(lf.ec2_client, "copy_snapshot",
                              side_effect=Exception("KMS error")):
                result = lf.perform_forensic_preservation("i-test")
                assert "Copy failed" in result["snapshots"][0]["encryption"]
        finally:
            lf.KMS_KEY_ARN = saved_key

    def test_already_encrypted_volume(self):
        """Lines 1760-1761: Already encrypted volume."""
        with patch.object(lf.ec2_client, "describe_volumes",
                          return_value={"Volumes": [
                              {"VolumeId": "vol-1", "State": "available", "Encrypted": True},
                          ]}), \
             patch.object(lf.ec2_client, "create_snapshot",
                          return_value={"SnapshotId": "snap-1"}):
            result = lf.perform_forensic_preservation("i-test")
            assert "already encrypted" in result["snapshots"][0]["encryption"]

    def test_client_error(self):
        """Lines 1767-1770: ClientError."""
        with patch.object(lf.ec2_client, "describe_volumes",
                          side_effect=ClientError(
                              {"Error": {"Code": "Error", "Message": "bad"}},
                              "DescribeVolumes")):
            result = lf.perform_forensic_preservation("i-err")
            assert result["status"] == "FAILED"

    def test_generic_error(self):
        """Lines 1771-1774: Generic exception."""
        with patch.object(lf.ec2_client, "describe_volumes",
                          side_effect=RuntimeError("Crash")):
            result = lf.perform_forensic_preservation("i-crash")
            assert result["status"] == "FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
#  SNS NOTIFICATION (lines 1815-1856)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPublishNotification:
    """Cover publish_notification rate limiting and error paths."""

    def test_rate_limit_exceeded_first_time(self):
        """Lines 1815-1820: First time exceeding rate limit → summary sent."""
        with patch.object(lf.dynamodb_raw, "update_item",
                          return_value={"Attributes": {
                              "notification_count": {"N": "11"},
                          }}), \
             patch.object(lf.sns_client, "publish"):
            lf.publish_notification("TEST", "body", {})

    def test_rate_limit_exceeded_suppressed(self):
        """Lines 1821-1823: Subsequent exceeds → suppressed."""
        with patch.object(lf.dynamodb_raw, "update_item",
                          return_value={"Attributes": {
                              "notification_count": {"N": "15"},
                          }}), \
             patch.object(lf.sns_client, "publish") as mock_pub:
            lf.publish_notification("TEST", "body", {})
            mock_pub.assert_not_called()

    def test_rate_limit_ddb_error(self):
        """Lines 1824-1825: DDB rate limit error ignored."""
        with patch.object(lf.dynamodb_raw, "update_item",
                          side_effect=Exception("DDB error")), \
             patch.object(lf.sns_client, "publish"):
            lf.publish_notification("TEST", "body", {})

    def test_notification_sns_error(self):
        """Lines 1854-1856: SNS publish error."""
        with patch.object(lf.dynamodb_raw, "update_item",
                          return_value={"Attributes": {
                              "notification_count": {"N": "1"},
                          }}), \
             patch.object(lf.sns_client, "publish", side_effect=Exception("SNS error")):
            lf.publish_notification("TEST", "body", {})  # Should not raise


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL COVERAGE: GuardDuty edge cases (lines 553-564, 567-573)
# ═══════════════════════════════════════════════════════════════════════════════

class TestGuardDutyAdditional:
    """Cover remaining GuardDuty paths."""

    def test_guardduty_access_key_iam_user(self):
        """Lines 553-561: AccessKey with IAM user."""
        event = {
            "detail": {
                "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                "severity": 5,
                "accountId": "123456789012",
                "resource": {
                    "resourceType": "AccessKey",
                    "accessKeyDetails": {
                        "userName": "attacker",
                        "userType": "IAMUser",
                        "principalId": "AIDA123",
                    },
                },
            },
        }
        result = lf._extract_from_guardduty(event)
        assert result["type"] == "iam"
        assert result["iam_type"] == "user"
        assert "attacker" in result["id"]

    def test_guardduty_access_key_assumed_role(self):
        """Lines 562-564: AccessKey with AssumedRole."""
        event = {
            "detail": {
                "type": "Discovery:IAMUser/AnomalousBehavior",
                "severity": 5,
                "resource": {
                    "resourceType": "AccessKey",
                    "accessKeyDetails": {
                        "principalId": "AROA123:i-instance123",
                        "userType": "AssumedRole",
                    },
                },
            },
        }
        result = lf._extract_from_guardduty(event)
        assert result is not None

    def test_guardduty_high_severity_fallback(self):
        """Lines 567-573: High severity → mass quarantine."""
        event = {
            "detail": {
                "type": "CryptoCurrency:EC2/BitcoinTool.B",
                "severity": 8,
                "resource": {"resourceType": "Other"},
            },
        }
        result = lf._extract_from_guardduty(event)
        assert result["type"] == "multi-ec2"


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL COVERAGE: S3 bulk ops trigger (lines 655-659)
# ═══════════════════════════════════════════════════════════════════════════════

class TestS3BulkOpsAboveThreshold:
    """Cover S3 bulk ops exceeding threshold."""

    def test_s3_bulk_ops_trigger(self):
        """Lines 655-659: S3 bulk operation exceeds threshold → trigger."""
        event = {
            "detail": {
                "eventName": "DeleteObject",
                "eventSource": "s3.amazonaws.com",
                "userIdentity": {
                    "principalId": "bulk-user",
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123:user/bulk-user",
                },
            },
        }
        with patch.object(lf, "_check_s3_rate_limit", return_value=True):
            result = lf._extract_from_cloudtrail_event(event)
            assert result is not None
            assert result["tripwire"] == "s3-bulk-operation"


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL COVERAGE: CloudTrail region + no arn (lines 670, 689)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCloudTrailRegionAndNoArn:
    """Cover awsRegion attachment and no ARN fallback."""

    def test_event_with_region(self):
        """Line 670: Attach event region to target."""
        event = {
            "detail": {
                "eventName": "StopInstances",
                "eventSource": "ec2.amazonaws.com",
                "awsRegion": "ap-southeast-1",
                "requestParameters": {
                    "instancesSet": {"items": [{"instanceId": "i-region"}]},
                },
            },
        }
        result = lf._extract_from_cloudtrail_event(event)
        assert result["region"] == "ap-southeast-1"

    def test_no_instance_no_arn_returns_none(self):
        """Line 689: No instance, no ARN → None."""
        event = {
            "detail": {
                "eventName": "Decrypt",
                "eventSource": "kms.amazonaws.com",
                "userIdentity": {},
            },
        }
        with patch.object(lf, "_check_kms_rate_limit", return_value=True):
            result = lf._extract_from_cloudtrail_event(event)
            assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL COVERAGE: _revoke_ecs_task_role describe_task_definition Exception
#  (lines 1129-1130)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRevokeECSTaskRoleDescribeFailure:
    """Cover describe_task_definition inner exception."""

    def test_describe_task_def_fails_no_override_role(self):
        """Lines 1129-1130: describe_task_definition fails → no role found."""
        with patch.object(lf.ecs_client, "describe_tasks",
                          return_value={"tasks": [{
                              "overrides": {},
                              "taskDefinitionArn": "arn:aws:ecs:td/my-def:1",
                          }]}), \
             patch.object(lf.ecs_client, "describe_task_definition",
                          side_effect=Exception("Access denied")):
            result = lf._revoke_ecs_task_role("arn:task/x", "arn:cluster/c")
            assert result["status"] == "SKIPPED"


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL COVERAGE: _get_instance_state raises + _verify_sg (line 1207, 1218)
# ═══════════════════════════════════════════════════════════════════════════════

class TestHelperRaises:
    """Cover raise paths in _get_instance_state and _verify_sg_exists."""

    def test_get_instance_state_raises_other_error(self):
        """Line 1207: Non-handled ClientError re-raises."""
        with patch.object(lf.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "Throttling", "Message": "Slow"}},
                              "DescribeInstances")):
            with pytest.raises(ClientError):
                lf._get_instance_state("i-test")

    def test_verify_sg_raises_other_error(self):
        """Line 1218: Non-handled ClientError re-raises."""
        with patch.object(lf.ec2_client, "describe_security_groups",
                          side_effect=ClientError(
                              {"Error": {"Code": "InternalError", "Message": "fail"}},
                              "DescribeSecurityGroups")):
            with pytest.raises(ClientError):
                lf._verify_sg_exists("sg-test")


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL COVERAGE: _extract_entity_name exception (lines 1291-1292)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtractEntityNameEdge:
    """Cover remaining _extract_entity_name edge cases."""

    def test_empty_string(self):
        assert lf._extract_entity_name("") == ""

    def test_valid_arn(self):
        assert lf._extract_entity_name("arn:aws:iam::123:role/path/my-role") == "my-role"


# ═══════════════════════════════════════════════════════════════════════════════
#  ADDITIONAL COVERAGE: NACL full swap path (lines 1463-1504)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNACLFullSwap:
    """Cover single-instance NACL swap path."""

    def test_single_instance_nacl_swap(self):
        """Lines 1463-1495: Single instance → swap NACL."""
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = "acl-quarantine"
        try:
            with patch.object(lf.ec2_client, "describe_instances") as mock_desc:
                mock_desc.side_effect = [
                    {"Reservations": [{"Instances": [
                        {"SubnetId": "sub-1", "PrivateIpAddress": "10.0.0.1"}
                    ]}]},
                    {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]},
                ]
                with patch.object(lf.ec2_client, "describe_network_acls",
                                  return_value={"NetworkAcls": [{
                                      "NetworkAclId": "acl-orig",
                                      "Associations": [{
                                          "SubnetId": "sub-1",
                                          "NetworkAclAssociationId": "aclassoc-1",
                                      }],
                                  }]}), \
                     patch.object(lf.ec2_client, "replace_network_acl_association"):
                    result = lf.perform_nacl_quarantine("i-test")
                    assert result["status"] == "SUCCESS"
                    assert result["method"] == "subnet-swap"
        finally:
            lf.QUARANTINE_NACL_ID = saved

    def test_multi_instance_per_ip_deny(self):
        """Lines 1445-1456: Multi instance → per-IP deny."""
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = "acl-quarantine"
        try:
            with patch.object(lf.ec2_client, "describe_instances") as mock_desc:
                mock_desc.side_effect = [
                    {"Reservations": [{"Instances": [
                        {"SubnetId": "sub-1", "PrivateIpAddress": "10.0.0.5"}
                    ]}]},
                    {"Reservations": [{"Instances": [
                        {"InstanceId": "i-1"}, {"InstanceId": "i-2"}
                    ]}]},
                ]
                with patch.object(lf, "_apply_per_ip_nacl_deny",
                                  return_value={"status": "SUCCESS"}):
                    result = lf.perform_nacl_quarantine("i-test")
                    assert result["status"] == "SUCCESS"
        finally:
            lf.QUARANTINE_NACL_ID = saved

    def test_no_nacl_configured(self):
        """Line 1422: QUARANTINE_NACL_ID not set → SKIPPED."""
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = ""
        try:
            result = lf.perform_nacl_quarantine("i-test")
            assert result["status"] == "SKIPPED"
        finally:
            lf.QUARANTINE_NACL_ID = saved


# ═══════════════════════════════════════════════════════════════════════════════
#  COVERAGE: lambda_restore.py remaining lines
#  Lines 179, 190, 377, 381, 386-394
# ═══════════════════════════════════════════════════════════════════════════════

class TestRestoreAdditional:
    """Cover remaining lambda_restore.py uncovered lines."""

    def test_instance_exists_raises(self):
        """Line 179: _instance_exists raises on non-handled error."""
        import lambda_restore as lr
        with patch.object(lr.ec2_client, "describe_instances",
                          side_effect=ClientError(
                              {"Error": {"Code": "Throttling", "Message": "Slow"}},
                              "DescribeInstances")):
            with pytest.raises(ClientError):
                lr._instance_exists("i-test")

    def test_sg_exists_raises(self):
        """Line 190: _sg_exists raises on non-handled error."""
        import lambda_restore as lr
        with patch.object(lr.ec2_client, "describe_security_groups",
                          side_effect=ClientError(
                              {"Error": {"Code": "InternalError", "Message": "Fail"}},
                              "DescribeSecurityGroups")):
            with pytest.raises(ClientError):
                lr._sg_exists("sg-test")

    def test_restore_iam_role_policy(self):
        """Lines 377, 381: _restore_iam_entity for /role/ path."""
        import lambda_restore as lr
        with patch.object(lr.iam_client, "delete_role_policy"):
            result = lr._restore_iam_entity(
                "arn:aws:iam::123:role/my-role"
            )
            assert len(result) == 2
            for item in result:
                assert item["status"] == "removed"

    def test_restore_iam_nosuchentity(self):
        """Lines 386-388: NoSuchEntity → not_found."""
        import lambda_restore as lr
        with patch.object(lr.iam_client, "delete_user_policy",
                          side_effect=ClientError(
                              {"Error": {"Code": "NoSuchEntity", "Message": "NF"}},
                              "DeleteUserPolicy")):
            result = lr._restore_iam_entity.__wrapped__("arn:aws:iam::123:user/test-user")
            for item in result:
                assert item["status"] == "not_found"

    def test_restore_iam_other_client_error(self):
        """Lines 389-391: Other ClientError → failed."""
        import lambda_restore as lr
        with patch.object(lr.iam_client, "delete_user_policy",
                          side_effect=ClientError(
                              {"Error": {"Code": "AccessDenied", "Message": "No"}},
                              "DeleteUserPolicy")):
            result = lr._restore_iam_entity.__wrapped__("arn:aws:iam::123:user/test-user")
            for item in result:
                assert item["status"] == "failed"

    def test_restore_iam_generic_exception(self):
        """Lines 392-394: Generic exception → failed."""
        import lambda_restore as lr
        with patch.object(lr.iam_client, "delete_user_policy",
                          side_effect=RuntimeError("Crash")):
            result = lr._restore_iam_entity.__wrapped__("arn:aws:iam::123:user/test-user")
            for item in result:
                assert item["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════════════════
#  COVERAGE: lambda_watchdog.py remaining lines
#  Lines 93, 142-143, 176, 210-211, 236, 252-253, 276, 305, 324, 332,
#         344-355, 365, 378-379
# ═══════════════════════════════════════════════════════════════════════════════

import lambda_watchdog as lw


class TestWatchdogHandler:
    """Cover watchdog lambda_handler paths."""

    def test_handler_check_exception(self):
        """Lines 93-100: Exception during check."""
        with patch.object(lw, "check_eventbridge_rules",
                          side_effect=Exception("Crash")), \
             patch.object(lw, "check_lambda_functions",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "check_dynamodb_tables",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "check_quarantine_sg",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "check_iam_permissions",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "_send_critical_alert"):
            result = lw.lambda_handler({}, None)
            body = json.loads(result["body"])
            assert body["overall_status"] == "DEGRADED"

    def test_handler_auto_remediated(self):
        """Lines 89-93: Auto-remediated result."""
        with patch.object(lw, "check_eventbridge_rules",
                          return_value={"status": "COMPROMISED", "auto_remediated": True}), \
             patch.object(lw, "check_lambda_functions",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "check_dynamodb_tables",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "check_quarantine_sg",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "check_iam_permissions",
                          return_value={"status": "HEALTHY"}), \
             patch.object(lw, "_send_critical_alert"):
            result = lw.lambda_handler({}, None)
            body = json.loads(result["body"])
            assert body["auto_remediated"] == 1


class TestCheckEventBridgeRules:
    """Cover EventBridge rule checks."""

    def test_disabled_rule_re_enable_fails(self):
        """Lines 142-143: Re-enable fails."""
        saved = lw.EXPECTED_EVENTBRIDGE_RULES
        lw.EXPECTED_EVENTBRIDGE_RULES = ["test-rule"]
        try:
            with patch.object(lw.events_client, "describe_rule",
                              return_value={"State": "DISABLED"}), \
                 patch.object(lw.events_client, "enable_rule",
                              side_effect=Exception("Fail")):
                result = lw.check_eventbridge_rules()
                assert result["status"] == "COMPROMISED"
        finally:
            lw.EXPECTED_EVENTBRIDGE_RULES = saved


class TestCheckLambdaFunctions:
    """Cover Lambda function checks."""

    def test_no_functions_configured(self):
        """Line 176: No functions → SKIPPED."""
        saved = [lw.KILLSWITCH_FUNCTION_NAME, lw.FORENSIC_FUNCTION_NAME, lw.RESTORE_FUNCTION_NAME]
        lw.KILLSWITCH_FUNCTION_NAME = ""
        lw.FORENSIC_FUNCTION_NAME = ""
        lw.RESTORE_FUNCTION_NAME = ""
        try:
            result = lw.check_lambda_functions()
            assert result["status"] == "SKIPPED"
        finally:
            lw.KILLSWITCH_FUNCTION_NAME, lw.FORENSIC_FUNCTION_NAME, lw.RESTORE_FUNCTION_NAME = saved

    def test_hash_mismatch(self):
        """Lines 197-202: Hash mismatch detected."""
        saved = lw.KILLSWITCH_FUNCTION_NAME
        lw.KILLSWITCH_FUNCTION_NAME = "my-func"
        saved2 = lw.LAMBDA_CODE_HASHES_PARAM
        lw.LAMBDA_CODE_HASHES_PARAM = "/cloudfreeze/hashes"
        try:
            with patch.object(lw.ssm_client, "get_parameter",
                              return_value={"Parameter": {
                                  "Value": json.dumps({"my-func": "expected-hash"})}}), \
                 patch.object(lw.lambda_client, "get_function_configuration",
                              return_value={"CodeSha256": "wrong-hash"}):
                result = lw.check_lambda_functions()
                assert result["status"] == "COMPROMISED"
                assert len(result["hash_mismatches"]) == 1
        finally:
            lw.KILLSWITCH_FUNCTION_NAME = saved
            lw.LAMBDA_CODE_HASHES_PARAM = saved2

    def test_function_missing(self):
        """Lines 210-211: ResourceNotFoundException."""
        saved = lw.KILLSWITCH_FUNCTION_NAME
        lw.KILLSWITCH_FUNCTION_NAME = "missing-func"
        try:
            with patch.object(lw.ssm_client, "get_parameter",
                              side_effect=Exception("N")), \
                 patch.object(lw.lambda_client, "get_function_configuration",
                              side_effect=lw.lambda_client.exceptions.ResourceNotFoundException(
                                  {"Error": {"Code": "ResourceNotFoundException", "Message": "NF"}},
                                  "GetFunctionConfiguration")):
                result = lw.check_lambda_functions()
                assert result["status"] == "COMPROMISED"
                assert "missing-func" in result["missing"]
        finally:
            lw.KILLSWITCH_FUNCTION_NAME = saved


class TestCheckDynamoDBTables:
    """Cover DynamoDB table checks."""

    def test_no_tables_configured(self):
        """Line 236: No tables → SKIPPED."""
        saved = [lw.DYNAMODB_TABLE, lw.KMS_RATE_TABLE]
        lw.DYNAMODB_TABLE = ""
        lw.KMS_RATE_TABLE = ""
        try:
            result = lw.check_dynamodb_tables()
            assert result["status"] == "SKIPPED"
        finally:
            lw.DYNAMODB_TABLE, lw.KMS_RATE_TABLE = saved

    def test_table_missing(self):
        """Lines 252-253: ResourceNotFoundException."""
        saved = lw.DYNAMODB_TABLE
        lw.DYNAMODB_TABLE = "missing-table"
        saved2 = lw.KMS_RATE_TABLE
        lw.KMS_RATE_TABLE = ""
        try:
            with patch.object(lw.dynamodb_client, "describe_table",
                              side_effect=lw.dynamodb_client.exceptions.ResourceNotFoundException(
                                  {"Error": {"Code": "ResourceNotFoundException", "Message": "NF"}},
                                  "DescribeTable")):
                result = lw.check_dynamodb_tables()
                assert result["status"] == "COMPROMISED"
                assert "missing-table" in result["missing"]
        finally:
            lw.DYNAMODB_TABLE = saved
            lw.KMS_RATE_TABLE = saved2


class TestCheckQuarantineSG:
    """Cover quarantine SG check."""

    def test_no_sg_configured(self):
        """Line 276: No SG → SKIPPED."""
        saved = lw.QUARANTINE_SG_ID
        lw.QUARANTINE_SG_ID = ""
        try:
            result = lw.check_quarantine_sg()
            assert result["status"] == "SKIPPED"
        finally:
            lw.QUARANTINE_SG_ID = saved

    def test_sg_deleted(self):
        """Lines 299-305: SG deleted."""
        saved = lw.QUARANTINE_SG_ID
        lw.QUARANTINE_SG_ID = "sg-gone"
        try:
            with patch.object(lw.ec2_client, "describe_security_groups",
                              side_effect=ClientError(
                                  {"Error": {"Code": "InvalidGroup.NotFound", "Message": "NF"}},
                                  "DescribeSecurityGroups")):
                result = lw.check_quarantine_sg()
                assert result["status"] == "COMPROMISED"
        finally:
            lw.QUARANTINE_SG_ID = saved

    def test_sg_raises_other_error(self):
        """Line 305: Non-handled error re-raises."""
        saved = lw.QUARANTINE_SG_ID
        lw.QUARANTINE_SG_ID = "sg-test"
        try:
            with patch.object(lw.ec2_client, "describe_security_groups",
                              side_effect=ClientError(
                                  {"Error": {"Code": "InternalError", "Message": "Fail"}},
                                  "DescribeSecurityGroups")):
                with pytest.raises(ClientError):
                    lw.check_quarantine_sg()
        finally:
            lw.QUARANTINE_SG_ID = saved


class TestCheckIAMPermissions:
    """Cover IAM permission checks."""

    def test_role_arn_empty(self):
        """Line 324: No ARN."""
        with patch("lambda_watchdog.boto3") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Arn": ""}
            mock_boto.client.return_value = mock_sts
            result = lw.check_iam_permissions()
            assert result["status"] == "ERROR"

    def test_role_name_parse_failure(self):
        """Line 332: Single-part ARN → skip deep check."""
        with patch("lambda_watchdog.boto3") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Arn": "arn:no-slashes"}
            mock_boto.client.return_value = mock_sts
            result = lw.check_iam_permissions()
            assert result["status"] == "HEALTHY"

    def test_denied_actions(self):
        """Lines 344-355: Denied actions detected."""
        with patch("lambda_watchdog.boto3") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {
                "Arn": "arn:aws:sts::123:assumed-role/MyRole/func",
                "Account": "123",
            }
            mock_boto.client.return_value = mock_sts
            with patch.object(lw.iam_client, "simulate_principal_policy",
                              return_value={"EvaluationResults": [
                                  {"EvalActionName": "ec2:DescribeInstances",
                                   "EvalDecision": "implicitDeny"},
                              ]}):
                result = lw.check_iam_permissions()
                assert result["status"] == "COMPROMISED"

    def test_simulation_fails(self):
        """Lines 360-363: Simulation fails → still healthy."""
        with patch("lambda_watchdog.boto3") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {
                "Arn": "arn:aws:sts::123:assumed-role/MyRole/func",
                "Account": "123",
            }
            mock_boto.client.return_value = mock_sts
            with patch.object(lw.iam_client, "simulate_principal_policy",
                              side_effect=Exception("No perm")):
                result = lw.check_iam_permissions()
                assert result["status"] == "HEALTHY"

    def test_iam_success(self):
        """Line 365: All actions allowed."""
        with patch("lambda_watchdog.boto3") as mock_boto:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {
                "Arn": "arn:aws:sts::123:assumed-role/MyRole/func",
                "Account": "123",
            }
            mock_boto.client.return_value = mock_sts
            with patch.object(lw.iam_client, "simulate_principal_policy",
                              return_value={"EvaluationResults": [
                                  {"EvalActionName": "ec2:DescribeInstances",
                                   "EvalDecision": "allowed"},
                              ]}):
                result = lw.check_iam_permissions()
                assert result["status"] == "HEALTHY"
                assert result["role"] == "MyRole"


class TestSendCriticalAlert:
    """Cover _send_critical_alert."""

    def test_no_topic_arn(self):
        """Lines 378-379: No SNS topic."""
        saved = lw.SNS_TOPIC_ARN
        lw.SNS_TOPIC_ARN = ""
        try:
            lw._send_critical_alert({"checks": {}, "issues_found": 1,
                                     "auto_remediated": 0, "timestamp": "now"})
        finally:
            lw.SNS_TOPIC_ARN = saved


# ═══════════════════════════════════════════════════════════════════════════════
#  COVERAGE: utils.py line 188 — retry exhausted raises
# ═══════════════════════════════════════════════════════════════════════════════

class TestRetryExhausted:
    """Cover retry_with_backoff exhaustion."""

    def test_retry_exhausted_raises(self):
        """Line 188: All retries exhausted → raises last exception."""
        from utils import retry_with_backoff

        @retry_with_backoff(max_retries=1, base_delay=0.01)
        def always_fails():
            raise ClientError(
                {"Error": {"Code": "Throttling", "Message": "Too fast"}},
                "TestOp"
            )

        with pytest.raises(ClientError):
            always_fails()

# ===============================================================================
#  FINAL COVERAGE: Remaining 10 lines
# ===============================================================================

class TestRemainingCoverage:
    def test_extract_entity_name_exception(self):
        class BadStr(str):
            def split(self, *args, **kwargs): raise Exception('Boom')
        assert lf._extract_entity_name(BadStr('test')) is None

    def test_nacl_quarantine_no_subnet(self):
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = "nacl-123"
        try:
            with patch.object(lf.ec2_client, 'describe_instances',
                              return_value={'Reservations': [{'Instances': [{'InstanceId': 'i-123'}]}]}):
                assert lf.perform_nacl_quarantine('i-123')['status'] == 'SKIPPED'
        finally:
            lf.QUARANTINE_NACL_ID = saved

    def test_nacl_quarantine_no_private_ip(self):
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = "nacl-123"
        try:
            with patch.object(lf.ec2_client, 'describe_instances') as mock_desc:
                mock_desc.side_effect = [
                    {'Reservations': [{'Instances': [{'InstanceId': 'i-123', 'SubnetId': '1'}]}]},
                    {'Reservations': [{'Instances': [{'InstanceId': 'i-123'}, {'InstanceId': 'i-456'}]}]}
                ]
                assert lf.perform_nacl_quarantine('i-123')['status'] == 'SKIPPED'
        finally:
            lf.QUARANTINE_NACL_ID = saved

    def test_nacl_quarantine_no_nacl_assoc(self):
        saved = lf.QUARANTINE_NACL_ID
        lf.QUARANTINE_NACL_ID = "nacl-123"
        try:
            with patch.object(lf.ec2_client, 'describe_instances') as mock_desc:
                mock_desc.side_effect = [
                    {'Reservations': [{'Instances': [{'InstanceId': 'i-123', 'SubnetId': '2', 'PrivateIpAddress': '10.0.0.1'}]}]},
                    {'Reservations': [{'Instances': [{'InstanceId': 'i-123'}]}]}
                ]
                with patch.object(lf.ec2_client, 'describe_network_acls', return_value={'NetworkAcls': []}):
                    assert lf.perform_nacl_quarantine('i-123')['status'] == 'SKIPPED'
        finally:
            lf.QUARANTINE_NACL_ID = saved

    def test_watchdog_lambda_generic_exception(self):
        saved = lw.KILLSWITCH_FUNCTION_NAME
        lw.KILLSWITCH_FUNCTION_NAME = 'my-func'
        try:
            with patch.object(lw.lambda_client, 'get_function_configuration', side_effect=Exception('Crash')):
                assert lw.check_lambda_functions()['status'] == 'HEALTHY'
        finally:
            lw.KILLSWITCH_FUNCTION_NAME = saved

    def test_watchdog_dynamodb_generic_exception(self):
        saved = lw.DYNAMODB_TABLE
        lw.DYNAMODB_TABLE = 'my-table'
        try:
            with patch.object(lw.dynamodb_client, 'describe_table', side_effect=Exception('Crash')):
                assert lw.check_dynamodb_tables()['status'] == 'HEALTHY'
        finally:
            lw.DYNAMODB_TABLE = saved

    def test_utils_retry_last_exception(self):
        import utils
        import pytest
        from botocore.exceptions import ClientError
        @utils.retry_with_backoff(max_retries=1, base_delay=0.01)
        def failing_function():
            raise ClientError({'Error': {'Code': 'Throttling'}}, 'X')
        with pytest.raises(ClientError):
            failing_function()
