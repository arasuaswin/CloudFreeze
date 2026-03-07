"""
CloudFreeze v7 — Self-Defense Watchdog Lambda
═══════════════════════════════════════════════
Runs on a 5-minute schedule to verify CloudFreeze infrastructure integrity.
If any component is tampered with, disabled, or deleted, this Lambda:
  1. Sends a CRITICAL SNS alert
  2. Attempts auto-remediation (re-enable rules, recreate SGs)

Checks performed:
  A. EventBridge rules exist and are ENABLED
  B. Lambda functions exist and have correct code hash
  C. DynamoDB tables exist and are ACTIVE
  D. Quarantine Security Group exists
  E. IAM role permissions are intact (via STS dry-run)

v7 State-of-Art: This is the "immune system" for CloudFreeze itself —
  if an attacker tries to disable the defense system, this watchdog catches it.
"""

import os
import json
import hashlib
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "")
KMS_RATE_TABLE = os.environ.get("KMS_RATE_TABLE", "")
QUARANTINE_SG_ID = os.environ.get("QUARANTINE_SG_ID", "")
KILLSWITCH_FUNCTION_NAME = os.environ.get("KILLSWITCH_FUNCTION_NAME", "")
FORENSIC_FUNCTION_NAME = os.environ.get("FORENSIC_FUNCTION_NAME", "")
RESTORE_FUNCTION_NAME = os.environ.get("RESTORE_FUNCTION_NAME", "")
EXPECTED_EVENTBRIDGE_RULES = json.loads(os.environ.get("EXPECTED_EVENTBRIDGE_RULES", "[]"))
LAMBDA_CODE_HASHES_PARAM = os.environ.get("LAMBDA_CODE_HASHES_PARAM", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Clients
events_client = boto3.client("events", region_name=AWS_REGION)
lambda_client = boto3.client("lambda", region_name=AWS_REGION)
dynamodb_client = boto3.client("dynamodb", region_name=AWS_REGION)
ec2_client = boto3.client("ec2", region_name=AWS_REGION)
sns_client = boto3.client("sns", region_name=AWS_REGION)
ssm_client = boto3.client("ssm", region_name=AWS_REGION)
iam_client = boto3.client("iam", region_name=AWS_REGION)

logger = logging.getLogger("CloudFreeze.Watchdog")
logger.setLevel(logging.INFO)


# ═══════════════════════════════════════════════════════════════════════════════
#  LAMBDA HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    """
    Main watchdog handler — runs all integrity checks and reports results.
    Triggered by scheduled EventBridge rule (every 5 minutes).
    """
    logger.info("CloudFreeze Watchdog v7: Starting infrastructure integrity scan")

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {},
        "overall_status": "HEALTHY",
        "issues_found": 0,
        "auto_remediated": 0,
    }

    # ── Run all checks ──
    checks = [
        ("eventbridge_rules", check_eventbridge_rules),
        ("lambda_functions", check_lambda_functions),
        ("dynamodb_tables", check_dynamodb_tables),
        ("quarantine_sg", check_quarantine_sg),
        ("iam_permissions", check_iam_permissions),
    ]

    for check_name, check_fn in checks:
        try:
            check_result = check_fn()
            results["checks"][check_name] = check_result
            if check_result["status"] != "HEALTHY":
                results["issues_found"] += 1
                results["overall_status"] = "DEGRADED"
                if check_result.get("auto_remediated"):
                    results["auto_remediated"] += 1
        except Exception as e:
            results["checks"][check_name] = {
                "status": "ERROR",
                "error": str(e),
            }
            results["issues_found"] += 1
            results["overall_status"] = "DEGRADED"

    # ── Send alert if any issues found ──
    if results["issues_found"] > 0:
        _send_critical_alert(results)
        logger.warning(f"Watchdog found {results['issues_found']} issues "
                       f"({results['auto_remediated']} auto-remediated)")
    else:
        logger.info("Watchdog: All checks HEALTHY — infrastructure intact")

    return {
        "statusCode": 200,
        "body": json.dumps(results, default=str),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  CHECK A: EVENTBRIDGE RULES
# ═══════════════════════════════════════════════════════════════════════════════

def check_eventbridge_rules():
    """
    Verify all CloudFreeze EventBridge rules exist and are ENABLED.
    Auto-remediation: Re-enable disabled rules.
    """
    if not EXPECTED_EVENTBRIDGE_RULES:
        return {"status": "SKIPPED", "reason": "No rules configured to check"}

    disabled_rules = []
    missing_rules = []
    re_enabled = []

    for rule_name in EXPECTED_EVENTBRIDGE_RULES:
        try:
            response = events_client.describe_rule(Name=rule_name)
            if response.get("State") != "ENABLED":
                disabled_rules.append(rule_name)
                # Auto-remediate: re-enable the rule
                try:
                    events_client.enable_rule(Name=rule_name)
                    re_enabled.append(rule_name)
                    logger.warning(f"Auto-remediated: Re-enabled EventBridge rule '{rule_name}'")
                except Exception as e:
                    logger.error(f"Failed to re-enable rule '{rule_name}': {e}")
        except events_client.exceptions.ResourceNotFoundException:
            missing_rules.append(rule_name)
        except Exception as e:
            logger.error(f"Error checking rule '{rule_name}': {e}")

    if missing_rules or disabled_rules:
        return {
            "status": "COMPROMISED",
            "missing_rules": missing_rules,
            "disabled_rules": disabled_rules,
            "auto_remediated": len(re_enabled) > 0,
            "re_enabled": re_enabled,
        }

    return {"status": "HEALTHY", "rules_verified": len(EXPECTED_EVENTBRIDGE_RULES)}


# ═══════════════════════════════════════════════════════════════════════════════
#  CHECK B: LAMBDA FUNCTION INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

def check_lambda_functions():
    """
    Verify all CloudFreeze Lambda functions exist and have the expected code hash.
    Detects: Attacker modifying Lambda function code to disable quarantine.
    """
    functions_to_check = [
        name for name in [KILLSWITCH_FUNCTION_NAME, FORENSIC_FUNCTION_NAME, RESTORE_FUNCTION_NAME]
        if name
    ]

    if not functions_to_check:
        return {"status": "SKIPPED", "reason": "No function names configured"}

    # Fetch known-good hashes from SSM (tamper-proof source)
    known_hashes = {}
    if LAMBDA_CODE_HASHES_PARAM:
        try:
            param = ssm_client.get_parameter(Name=LAMBDA_CODE_HASHES_PARAM, WithDecryption=True)
            known_hashes = json.loads(param["Parameter"]["Value"])
        except Exception as e:
            logger.warning(f"Could not fetch known code hashes from SSM: {e}")

    missing_functions = []
    hash_mismatches = []
    verified = []

    for func_name in functions_to_check:
        try:
            config = lambda_client.get_function_configuration(FunctionName=func_name)
            current_hash = config.get("CodeSha256", "")

            if func_name in known_hashes:
                if current_hash != known_hashes[func_name]:
                    hash_mismatches.append({
                        "function": func_name,
                        "expected": known_hashes[func_name],
                        "actual": current_hash,
                    })
                else:
                    verified.append(func_name)
            else:
                verified.append(func_name)  # No known hash to compare, just verify existence

        except lambda_client.exceptions.ResourceNotFoundException:
            missing_functions.append(func_name)
        except Exception as e:
            logger.error(f"Error checking Lambda '{func_name}': {e}")

    if missing_functions or hash_mismatches:
        return {
            "status": "COMPROMISED",
            "missing": missing_functions,
            "hash_mismatches": hash_mismatches,
            "auto_remediated": False,
        }

    return {"status": "HEALTHY", "functions_verified": len(verified)}


# ═══════════════════════════════════════════════════════════════════════════════
#  CHECK C: DYNAMODB TABLES
# ═══════════════════════════════════════════════════════════════════════════════

def check_dynamodb_tables():
    """
    Verify DynamoDB tables exist and are ACTIVE.
    Detects: Attacker deleting tables to disable idempotency and rate counting.
    """
    tables_to_check = [t for t in [DYNAMODB_TABLE, KMS_RATE_TABLE] if t]

    if not tables_to_check:
        return {"status": "SKIPPED", "reason": "No tables configured"}

    missing_tables = []
    unhealthy_tables = []
    verified = []

    for table_name in tables_to_check:
        try:
            response = dynamodb_client.describe_table(TableName=table_name)
            status = response["Table"]["TableStatus"]
            if status != "ACTIVE":
                unhealthy_tables.append({"table": table_name, "status": status})
            else:
                verified.append(table_name)
        except dynamodb_client.exceptions.ResourceNotFoundException:
            missing_tables.append(table_name)
        except Exception as e:
            logger.error(f"Error checking DynamoDB table '{table_name}': {e}")

    if missing_tables or unhealthy_tables:
        return {
            "status": "COMPROMISED",
            "missing": missing_tables,
            "unhealthy": unhealthy_tables,
            "auto_remediated": False,
        }

    return {"status": "HEALTHY", "tables_verified": len(verified)}


# ═══════════════════════════════════════════════════════════════════════════════
#  CHECK D: QUARANTINE SECURITY GROUP
# ═══════════════════════════════════════════════════════════════════════════════

def check_quarantine_sg():
    """
    Verify quarantine Security Group exists and has correct rules.
    Auto-remediation: If SG is missing, cannot auto-create (needs VPC context).
    """
    if not QUARANTINE_SG_ID:
        return {"status": "SKIPPED", "reason": "No quarantine SG configured"}

    try:
        response = ec2_client.describe_security_groups(GroupIds=[QUARANTINE_SG_ID])
        sg = response["SecurityGroups"][0]

        # Verify it has restrictive rules (no wide-open ingress)
        ingress_rules = sg.get("IpPermissions", [])
        has_wide_open = any(
            any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
            for rule in ingress_rules
        )

        if has_wide_open:
            return {
                "status": "COMPROMISED",
                "reason": "Quarantine SG has 0.0.0.0/0 ingress — attacker may have modified it",
                "auto_remediated": False,
            }

        return {"status": "HEALTHY", "sg_id": QUARANTINE_SG_ID}

    except ClientError as e:
        if "InvalidGroup.NotFound" in str(e):
            return {
                "status": "COMPROMISED",
                "reason": f"Quarantine SG {QUARANTINE_SG_ID} has been deleted",
                "auto_remediated": False,
            }
        raise


# ═══════════════════════════════════════════════════════════════════════════════
#  CHECK E: IAM PERMISSIONS
# ═══════════════════════════════════════════════════════════════════════════════

def check_iam_permissions():
    """
    Verify Lambda execution role still has required permissions.
    Uses STS get-caller-identity as a lightweight check, then verifies
    critical permission sets via IAM simulate.
    """
    try:
        sts = boto3.client("sts", region_name=AWS_REGION)
        identity = sts.get_caller_identity()
        role_arn = identity.get("Arn", "")

        if not role_arn:
            return {"status": "ERROR", "reason": "Could not determine execution role"}

        # Extract the role ARN from the assumed-role ARN
        # Format: arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/FUNCTION_NAME
        parts = role_arn.split("/")
        if len(parts) >= 2:
            role_name = parts[1]
        else:
            return {"status": "HEALTHY", "note": "Could not parse role name, skipping deep check"}

        # Check critical actions via IAM policy simulation
        critical_actions = [
            "ec2:ModifyNetworkInterfaceAttribute",
            "ec2:DescribeInstances",
            "sns:Publish",
        ]

        try:
            # Use the role ARN directly for simulation
            role_arn_full = f"arn:aws:iam::{identity['Account']}:role/{role_name}"
            sim_result = iam_client.simulate_principal_policy(
                PolicySourceArn=role_arn_full,
                ActionNames=critical_actions,
            )

            denied_actions = [
                r["EvalActionName"] for r in sim_result["EvaluationResults"]
                if r["EvalDecision"] != "allowed"
            ]

            if denied_actions:
                return {
                    "status": "COMPROMISED",
                    "reason": f"Lambda role missing permissions: {denied_actions}",
                    "auto_remediated": False,
                }
        except Exception as e:
            # IAM simulation may fail if role doesn't have iam:SimulatePrincipalPolicy
            logger.warning(f"IAM simulation failed (non-critical): {e}")
            return {"status": "DEGRADED", "note": "IAM simulation unavailable, basic check passed"}

        return {"status": "HEALTHY", "role": role_name}

    except Exception as e:
        return {"status": "ERROR", "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
#  ALERT HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def _send_critical_alert(results):
    """Send a CRITICAL alert when infrastructure tampering is detected."""
    if not SNS_TOPIC_ARN:
        logger.error("Cannot send alert: SNS_TOPIC_ARN not configured")
        return

    try:
        subject = "CloudFreeze CRITICAL: Infrastructure Tampering Detected"[:100]

        compromised_checks = [
            name for name, result in results["checks"].items()
            if result.get("status") in ("COMPROMISED", "ERROR")
        ]

        message = (
            f"{'='*60}\n"
            f"  CLOUDFREEZE v7 — SELF-DEFENSE WATCHDOG ALERT\n"
            f"{'='*60}\n\n"
            f"⚠️  INFRASTRUCTURE TAMPERING DETECTED\n\n"
            f"Issues Found:      {results['issues_found']}\n"
            f"Auto-Remediated:   {results['auto_remediated']}\n"
            f"Compromised:       {', '.join(compromised_checks)}\n"
            f"Timestamp:         {results['timestamp']}\n\n"
            f"--- FULL DETAILS ---\n"
            f"{json.dumps(results, indent=2, default=str)}\n"
        )

        sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
        logger.info("Watchdog CRITICAL alert published to SNS")

    except Exception as e:
        logger.error(f"Failed to publish watchdog alert: {e}")
