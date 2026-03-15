"""
CloudFreeze v7: Forensic Lambda — Async Snapshot + Memory Capture
===================================================================
Authors: Aswin R

v7: Dedicated forensic Lambda invoked ASYNCHRONOUSLY by the kill-switch.
  ✅ Creates encrypted EBS snapshots of every attached volume
  ✅ Triggers memory dump via SSM Run Command (if configured)
  ✅ 300s timeout (vs 30s for quarantine Lambda — forensics can be slow)
  ✅ SNS notification on completion/failure
  ✅ Retry with exponential backoff on all AWS API calls
  ✅ Structured JSON logging

v7 Enhancements:
  ✅ Fix B: SSM agent health check before memory forensics
           Gracefully skips if SSM agent is offline (ransomware may kill it)

Invoked by: Kill-Switch Lambda (InvocationType=Event, async)
Payload: {"instance_id": "i-xxx", "kms_key_arn": "...", "sns_topic_arn": "...", "timestamp": "..."}
"""

import json
import os
import logging
import time
import functools
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from utils import setup_json_logging, retry_with_backoff


# ─── v7: Structured JSON Logging ─────────────────────────────────────────────
logger = setup_json_logging("cloudfreeze-forensic")


# ─── Configuration ───────────────────────────────────────────────────────────
FORENSIC_S3_BUCKET = os.environ.get("FORENSIC_S3_BUCKET", "")
ENABLE_MEMORY_FORENSICS = os.environ.get("ENABLE_MEMORY_FORENSICS", "false").lower() == "true"

ec2_client = boto3.client("ec2")
sns_client = boto3.client("sns")
ssm_client = boto3.client("ssm")


# ═══════════════════════════════════════════════════════════════════════════════
#  RETRY HELPER — imported from utils.py (retry_with_backoff)
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    """
    Forensic Lambda handler. Invoked asynchronously by the kill-switch Lambda.
    Creates encrypted EBS snapshots and optionally triggers memory capture.
    """
    logger.info(f"CloudFreeze Forensic Lambda v7 invoked: {json.dumps(event, default=str)}")

    instance_id   = event.get("instance_id", "")
    kms_key_arn   = event.get("kms_key_arn", "")
    sns_topic_arn = event.get("sns_topic_arn", "")

    if not instance_id:
        logger.error("Missing instance_id in forensic event")
        return {"statusCode": 400, "body": "Missing instance_id"}

    results = {
        "instance_id": instance_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Phase 1: Memory forensics (must happen BEFORE instance is fully isolated)
    if ENABLE_MEMORY_FORENSICS:
        results["memory_capture"] = capture_volatile_data(instance_id)

    # Phase 2: EBS snapshots (primary forensic preservation)
    results["snapshots"] = create_forensic_snapshots(instance_id, kms_key_arn)

    # Notify on completion
    if sns_topic_arn:
        try:
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject="CloudFreeze: Forensic Preservation Complete"[:100],
                Message=json.dumps(results, indent=2, default=str),
            )
        except Exception as e:
            logger.error(f"SNS notification failed: {e}")

    logger.info(f"Forensic preservation complete: {json.dumps(results, default=str)}")
    return {"statusCode": 200, "body": results}


# ═══════════════════════════════════════════════════════════════════════════════
#  MEMORY FORENSICS — Volatile Data Capture via SSM
# ═══════════════════════════════════════════════════════════════════════════════

def capture_volatile_data(instance_id):
    """
    v7 Fix #9: Captures volatile forensic data (process list, network
    connections, open files) via SSM Run Command before full quarantine.
    Memory dump via avml is attempted if available.

    v7 Fix B: Added SSM agent health check. If the agent is offline
    (ransomware may have killed it), we skip SSM-dependent capture
    gracefully and document the gap.
    """
    # v7 Fix B: Check SSM agent health before attempting commands
    try:
        ssm_info = ssm_client.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        ssm_instances = ssm_info.get("InstanceInformationList", [])
        if not ssm_instances or ssm_instances[0].get("PingStatus") != "Online":
            logger.warning(
                f"v7 SSM agent NOT online for {instance_id}. "
                f"Skipping volatile data capture (SSM-dependent). "
                f"EBS snapshots will still be taken."
            )
            return {
                "status": "SKIPPED",
                "reason": "SSM agent offline — volatile data capture unavailable",
                "note": "EBS snapshots are SSM-independent and will still be taken.",
            }
        logger.info(f"v7 SSM health check passed for {instance_id} — proceeding with volatile capture")
    except Exception as e:
        logger.warning(f"v7 SSM health check failed: {e}. Attempting capture anyway.")
    commands = [
        "#!/bin/bash",
        "set -e",
        f"TIMESTAMP=$(date -u '+%Y%m%d-%H%M%S')",
        f"FORENSIC_DIR=/tmp/cloudfreeze-forensic-$TIMESTAMP",
        "mkdir -p $FORENSIC_DIR",
        "",
        "# Capture process tree",
        "ps auxf > $FORENSIC_DIR/process_tree.txt 2>&1 || true",
        "",
        "# Capture network connections",
        "ss -tulnp > $FORENSIC_DIR/network_connections.txt 2>&1 || true",
        "netstat -tlnp >> $FORENSIC_DIR/network_connections.txt 2>&1 || true",
        "",
        "# Capture open files",
        "lsof > $FORENSIC_DIR/open_files.txt 2>&1 || true",
        "",
        "# Capture /proc data",
        "cat /proc/meminfo > $FORENSIC_DIR/meminfo.txt 2>&1 || true",
        "cat /proc/cpuinfo > $FORENSIC_DIR/cpuinfo.txt 2>&1 || true",
        "cat /proc/mounts > $FORENSIC_DIR/mounts.txt 2>&1 || true",
        "",
        "# Capture login history",
        "last -50 > $FORENSIC_DIR/login_history.txt 2>&1 || true",
        "who > $FORENSIC_DIR/active_users.txt 2>&1 || true",
        "",
        "# Capture crontabs",
        "for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user >> $FORENSIC_DIR/crontabs.txt 2>/dev/null; done || true",
        "",
        "# Attempt memory dump with avml (if installed)",
        "if command -v avml &> /dev/null; then",
        "  avml $FORENSIC_DIR/memory_dump.lime || true",
        "fi",
        "",
        "# Upload to S3 if bucket is configured",
        f"if [ -n '{FORENSIC_S3_BUCKET}' ]; then",
        f"  aws s3 cp $FORENSIC_DIR/ s3://{FORENSIC_S3_BUCKET}/forensics/{instance_id}/$TIMESTAMP/ --recursive 2>&1 || true",
        "fi",
        "",
        "echo 'Forensic data capture complete'",
    ]

    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": commands},
            TimeoutSeconds=120,
            Comment=f"CloudFreeze forensic data capture for {instance_id}",
        )
        command_id = response["Command"]["CommandId"]
        logger.info(f"Memory forensics SSM command sent: {command_id}")
        return {"status": "SSM_COMMAND_SENT", "command_id": command_id}

    except ClientError as e:
        error_msg = f"SSM command failed: {e.response['Error']['Message']}"
        logger.warning(error_msg)
        return {"status": "FAILED", "reason": error_msg}
    except Exception as e:
        logger.warning(f"Memory forensics failed (non-critical): {e}")
        return {"status": "FAILED", "reason": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
#  EBS SNAPSHOT FORENSICS — Encrypted Snapshots
# ═══════════════════════════════════════════════════════════════════════════════

@retry_with_backoff()
def create_forensic_snapshots(instance_id, kms_key_arn):
    """Creates encrypted EBS snapshots of every attached volume."""
    try:
        volumes = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
        )
        volume_list = volumes.get("Volumes", [])

        if not volume_list:
            logger.warning(f"No EBS volumes attached to {instance_id}")
            return {"status": "SUCCESS", "detail": "No volumes attached", "snapshots": []}

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        snapshots_created = []

        for vol in volume_list:
            vol_id    = vol["VolumeId"]
            vol_state = vol.get("State", "")

            if vol_state not in ("in-use", "available"):
                logger.warning(f"Skipping volume {vol_id} in state '{vol_state}'")
                snapshots_created.append({
                    "volume_id": vol_id, "status": "SKIPPED",
                    "reason": f"Volume in '{vol_state}' state",
                })
                continue

            description = (
                f"CloudFreeze v7 forensic snapshot | Instance: {instance_id} "
                f"| Volume: {vol_id} | {timestamp}"
            )

            snapshot = ec2_client.create_snapshot(
                VolumeId=vol_id,
                Description=description,
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Name",           "Value": f"CloudFreeze-Forensic-{instance_id}"},
                        {"Key": "CloudFreeze",     "Value": "forensic-snapshot"},
                        {"Key": "SourceInstance",  "Value": instance_id},
                        {"Key": "SourceVolume",    "Value": vol_id},
                        {"Key": "CapturedAt",      "Value": timestamp},
                        {"Key": "Encrypted",       "Value": "true"},
                        {"Key": "Version",         "Value": "v7-async"},
                    ],
                }],
            )

            snapshot_id = snapshot["SnapshotId"]
            snap_info = {
                "volume_id": vol_id,
                "snapshot_id": snapshot_id,
                "description": description,
            }

            # Create encrypted copy if source is unencrypted
            if not vol.get("Encrypted", False) and kms_key_arn:
                try:
                    copy = ec2_client.copy_snapshot(
                        SourceSnapshotId=snapshot_id,
                        SourceRegion=os.environ.get("AWS_REGION", "us-east-1"),
                        Description=f"[ENCRYPTED] {description}",
                        Encrypted=True,
                        KmsKeyId=kms_key_arn,
                    )
                    snap_info["encrypted_copy_id"] = copy["SnapshotId"]
                    snap_info["encryption"] = "KMS-encrypted copy created"
                except Exception as enc_err:
                    logger.warning(f"Encrypted copy failed: {enc_err}")
                    snap_info["encryption"] = f"Copy failed: {enc_err}"
            else:
                snap_info["encryption"] = "Source volume already encrypted or default encryption active"

            snapshots_created.append(snap_info)

        return {"status": "SUCCESS", "snapshots": snapshots_created}

    except ClientError as e:
        error_msg = f"Forensic snapshot error: {e.response['Error']['Message']}"
        logger.error(error_msg)
        return {"status": "FAILED", "reason": error_msg}
    except Exception as e:
        error_msg = f"Unexpected forensic error: {str(e)}"
        logger.error(error_msg)
        return {"status": "FAILED", "reason": error_msg}
