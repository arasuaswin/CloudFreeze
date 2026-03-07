# ══════════════════════════════════════════════════════════════════════════════
#  CloudFreeze v7 — Outputs
# ══════════════════════════════════════════════════════════════════════════════

output "vpc_id" {
  description = "ID of the CloudFreeze VPC"
  value       = aws_vpc.main.id
}

output "target_instance_id" {
  description = "ID of the target EC2 instance"
  value       = aws_instance.target.id
}

output "target_instance_public_ip" {
  description = "Public IP of the target EC2 instance"
  value       = aws_instance.target.public_ip
}

output "quarantine_sg_id" {
  description = "ID of the Quarantine Security Group"
  value       = aws_security_group.quarantine.id
}

output "normal_sg_id" {
  description = "ID of the Normal Security Group"
  value       = aws_security_group.normal.id
}

output "honeytoken_bucket" {
  description = "Name of the S3 honeytoken bucket"
  value       = aws_s3_bucket.honeytoken.id
}

output "lambda_killswitch_arn" {
  description = "ARN of the Kill-Switch Lambda"
  value       = aws_lambda_function.killswitch.arn
}

output "lambda_restore_arn" {
  description = "ARN of the Restore Lambda"
  value       = aws_lambda_function.restore.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS alert topic"
  value       = aws_sns_topic.alerts.arn
}

output "dynamodb_table" {
  description = "Name of the DynamoDB incidents table"
  value       = aws_dynamodb_table.incidents.name
}

output "forensic_kms_key_arn" {
  description = "ARN of the KMS key for forensic snapshot encryption"
  value       = aws_kms_key.forensic.arn
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "ssm_connect_command" {
  description = "Command to connect to the target instance via SSM (no SSH needed)"
  value       = "aws ssm start-session --target ${aws_instance.target.id}"
}

# ── v3 Outputs ──────────────────────────────────────────────────────────────

output "killswitch_dlq_url" {
  description = "URL of the Kill-Switch Dead-Letter Queue"
  value       = aws_sqs_queue.killswitch_dlq.url
}

output "restore_dlq_url" {
  description = "URL of the Restore Dead-Letter Queue"
  value       = aws_sqs_queue.restore_dlq.url
}

output "dashboard_url" {
  description = "URL of the CloudWatch defense monitoring dashboard"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.cloudfreeze.dashboard_name}"
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector (if enabled)"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : "disabled"
}

# ── v4 REAL-TIME Outputs ─────────────────────────────────────────────────────

output "kms_rate_table" {
  description = "Name of the DynamoDB table for in-Lambda KMS rate counting"
  value       = aws_dynamodb_table.kms_rate.name
}

output "ssm_monitor_document" {
  description = "Name of the SSM document for the real-time instance monitoring agent"
  value       = aws_ssm_document.instance_monitor.name
}

# ── v7 OUTPUTS — New Resources ──────────────────────────────────────────────

output "quarantine_nacl_id" {
  description = "v7: Quarantine NACL ID for defense-in-depth network isolation"
  value       = aws_network_acl.quarantine.id
}

output "forensic_lambda_arn" {
  description = "v7: Forensic Lambda ARN (async snapshots + memory capture)"
  value       = aws_lambda_function.forensic.arn
}

output "forensic_s3_bucket" {
  description = "v7: S3 bucket for forensic memory dumps and volatile data"
  value       = aws_s3_bucket.forensic_data.id
}

output "subnet_b_id" {
  description = "v7: Second subnet (AZ b) for multi-AZ high availability"
  value       = aws_subnet.public_b.id
}

output "heartbeat_alarm" {
  description = "v7: Heartbeat alarm ARN — triggers when monitoring agent stops"
  value       = aws_cloudwatch_metric_alarm.agent_heartbeat.arn
}

output "ssm_canary_parameter" {
  description = "v7: SSM Parameter Store path for tamper-proof canary checksums"
  value       = aws_ssm_parameter.canary_checksums.name
}

# ═══════════════════════════════════════════════════════════════════════════════
#  v7: Edge-Case Elimination Outputs
# ═══════════════════════════════════════════════════════════════════════════════

output "watchdog_lambda_arn" {
  description = "v7: Self-defense watchdog Lambda ARN"
  value       = aws_lambda_function.watchdog.arn
}

output "watchdog_dlq_url" {
  description = "v7: Watchdog Dead Letter Queue URL"
  value       = aws_sqs_queue.watchdog_dlq.url
}

output "s3_bulk_ops_rule_arn" {
  description = "v7: S3 bulk operation detection EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.s3_bulk_ops_tripwire.arn
}

output "rds_protection_rule_arn" {
  description = "v7: RDS suspicious activity EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.rds_protection_tripwire.arn
}

output "self_defense_rule_arn" {
  description = "v7: Self-defense EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.self_defense_eventbridge.arn
}

output "lambda_code_hashes_param" {
  description = "v7: SSM Parameter for known-good Lambda code hashes"
  value       = aws_ssm_parameter.lambda_code_hashes.name
}
