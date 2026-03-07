# ══════════════════════════════════════════════════════════════════════════════
#  CloudFreeze v7 — Input Variables (with validation)
# ══════════════════════════════════════════════════════════════════════════════

variable "aws_region" {
  description = "AWS region to deploy CloudFreeze into"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address for SNS security alert notifications"
  type        = string
}

variable "project_name" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "cloudfreeze"
}

# ── Fix #1: KMS rate-based detection threshold ──────────────────────────────
variable "kms_call_threshold" {
  description = "Number of KMS Encrypt calls in 1 minute that triggers the alarm (tune to your baseline)"
  type        = number
  default     = 50

  validation {
    condition     = var.kms_call_threshold >= 10
    error_message = "kms_call_threshold must be at least 10 to avoid false positives."
  }
}

# ── Velocity tripwire thresholds ─────────────────────────────────────────────
variable "disk_write_threshold" {
  description = "DiskWriteOps threshold per minute that triggers the velocity alarm"
  type        = number
  default     = 1000

  validation {
    condition     = var.disk_write_threshold >= 100
    error_message = "disk_write_threshold must be at least 100."
  }
}

variable "cpu_threshold" {
  description = "CPU utilization percentage that triggers the velocity alarm"
  type        = number
  default     = 90

  validation {
    condition     = var.cpu_threshold >= 1 && var.cpu_threshold <= 100
    error_message = "cpu_threshold must be between 1 and 100."
  }
}

# ── v7 Fix #18: SSH CIDR hardening ──────────────────────────────────────────
variable "allowed_ssh_cidr" {
  description = "CIDR block for SSH access (v7: 0.0.0.0/0 blocked for security — use your IP/32)"
  type        = string
  default     = "10.0.0.0/32"  # Non-routable placeholder — override with your IP

  validation {
    condition     = var.allowed_ssh_cidr != "0.0.0.0/0"
    error_message = "SSH CIDR must NOT be 0.0.0.0/0 for security. Use your specific IP/32 instead."
  }
}

# ── Fix #14: GuardDuty toggle ───────────────────────────────────────────────
variable "enable_guardduty" {
  description = "Enable GuardDuty ML-based threat detection (set to false if already enabled in account)"
  type        = bool
  default     = true
}

# ── v7: Memory forensics toggle ─────────────────────────────────────────────
variable "enable_memory_forensics" {
  description = "Enable volatile memory capture via SSM (requires avml or similar on instances)"
  type        = bool
  default     = false
}

# ── v7 Fix 17: Parameterized instance configuration ───────────────────────
variable "instance_type" {
  description = "EC2 instance type for monitored instances"
  type        = string
  default     = "t3.micro"
}

variable "instance_count" {
  description = "Number of monitored instances to deploy"
  type        = number
  default     = 1

  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 10
    error_message = "Instance count must be between 1 and 10."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log group retention in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention value."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  v7: Edge-Case Elimination Variables
# ═══════════════════════════════════════════════════════════════════════════════

variable "file_change_rate_threshold" {
  description = "v7: Max file modifications per minute before triggering quarantine (slow encryption detection)"
  type        = number
  default     = 20

  validation {
    condition     = var.file_change_rate_threshold >= 5 && var.file_change_rate_threshold <= 500
    error_message = "File change rate threshold must be between 5 and 500."
  }
}

variable "s3_bulk_ops_threshold" {
  description = "v7: Max S3 DeleteObject/PutObject calls per minute per principal before quarantine"
  type        = number
  default     = 50

  validation {
    condition     = var.s3_bulk_ops_threshold >= 10 && var.s3_bulk_ops_threshold <= 1000
    error_message = "S3 bulk ops threshold must be between 10 and 1000."
  }
}

variable "watchdog_interval_minutes" {
  description = "v7: How often the self-defense watchdog runs (minutes)"
  type        = number
  default     = 5

  validation {
    condition     = var.watchdog_interval_minutes >= 1 && var.watchdog_interval_minutes <= 60
    error_message = "Watchdog interval must be between 1 and 60 minutes."
  }
}
