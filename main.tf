# ══════════════════════════════════════════════════════════════════════════════
#  CloudFreeze v7: 10/10 State-of-the-Art Ransomware Defense — Terraform
#  Authors: Aswin R & Vaishnavi SS Nyshadham
# ══════════════════════════════════════════════════════════════════════════════
#
#  v7 Upgrades (on top of v3/v4 22 fixes):
#    ✅ Fix 1–22: All previous fixes retained
#    ✅ Fix 23: Multi-AZ deployment (HA)
#    ✅ Fix 24: Multi-region CloudTrail
#    ✅ Fix 25: NACL quarantine (defense-in-depth)
#    ✅ Fix 26: Async forensic Lambda (quarantine never blocked)
#    ✅ Fix 27: Memory forensics via SSM
#    ✅ Fix 28: Systemd monitoring agent with heartbeat
#    ✅ Fix 29: DynamoDB throttle alarms
#    ✅ Fix 30: SSH CIDR hardening (no more 0.0.0.0/0 default)
#    ✅ Fix 31: External canary checksums (SSM Parameter Store)
#    ✅ Fix 32: Tag-based dynamic alarms
#    ✅ Fix 33: Structured JSON logging on all Lambdas
#
#  Deploy: terraform init && terraform apply -auto-approve -var="alert_email=you@example.com"
# ══════════════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # ── Fix #10: Remote State Backend (uncomment after creating the S3 bucket) ─
  # backend "s3" {
  #   bucket         = "cloudfreeze-tfstate-YOUR_ACCOUNT_ID"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "cloudfreeze-tflock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region
}

# ── Data Sources ─────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  prefix     = var.project_name
}


# ══════════════════════════════════════════════════════════════════════════════
#  1. NETWORKING — VPC, Subnet, IGW, Route Table, VPC Endpoints
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${local.region}a"
  tags                    = { Name = "${local.prefix}-public-subnet-a" }
}

# v7 Fix #2: Multi-AZ — second subnet for HA
resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${local.region}b"
  tags                    = { Name = "${local.prefix}-public-subnet-b" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${local.prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ── Fix #7 & #11: VPC Endpoints for quarantine visibility + SSM ─────────────
# These allow quarantined instances to still send CloudWatch logs/metrics
# and be accessed via SSM Session Manager.

resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.prefix}-vpce-sg"
  description = "Allow HTTPS from VPC to VPC Endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-vpce-sg" }
}

# SSM endpoints (Fix #11)
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public.id, aws_subnet.public_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${local.prefix}-vpce-ssm" }
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public.id, aws_subnet.public_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${local.prefix}-vpce-ssmmessages" }
}

resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public.id, aws_subnet.public_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${local.prefix}-vpce-ec2messages" }
}

# CloudWatch endpoints (for quarantine visibility)
resource "aws_vpc_endpoint" "cloudwatch_logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${local.prefix}-vpce-logs" }
}

resource "aws_vpc_endpoint" "cloudwatch_monitoring" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${local.region}.monitoring"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${local.prefix}-vpce-monitoring" }
}

# S3 Gateway endpoint (needed for CloudTrail, SSM, etc.)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]
  tags              = { Name = "${local.prefix}-vpce-s3" }
}

# ── Security Groups ──────────────────────────────────────────────────────────

# Normal SG: allows SSH and HTTP inbound (for testing)
resource "aws_security_group" "normal" {
  name        = "${local.prefix}-normal-sg"
  description = "Normal operating security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH (restricted)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-normal-sg" }
}

# Fix #7: QUARANTINE SG — Zero inbound, egress ONLY to VPC endpoints
resource "aws_security_group" "quarantine" {
  name        = "${local.prefix}-quarantine-sg"
  description = "CloudFreeze Quarantine — no inbound, egress only to VPC endpoints"
  vpc_id      = aws_vpc.main.id

  # No ingress rules — nothing comes in

  # Egress ONLY to VPC endpoints (HTTPS/443) for CloudWatch + SSM visibility
  egress {
    description     = "HTTPS to VPC Endpoints only"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.vpc_endpoints.id]
  }

  tags = {
    Name        = "${local.prefix}-quarantine-sg"
    CloudFreeze = "quarantine"
  }
}

# v7 Fix #8: QUARANTINE NACL — Defense-in-depth (blocks at subnet level)
resource "aws_network_acl" "quarantine" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = []  # Not associated by default — Lambda swaps during quarantine

  # Allow HTTPS outbound to VPC CIDR (for VPC endpoints only)
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 443
    to_port    = 443
  }

  # Allow ephemeral return traffic from VPC endpoints
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 1024
    to_port    = 65535
  }

  # Deny everything else (implicit deny, but explicit for visibility)
  egress {
    protocol   = "-1"
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "-1"
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name        = "${local.prefix}-quarantine-nacl"
    CloudFreeze = "quarantine-nacl"
  }
}


# ══════════════════════════════════════════════════════════════════════════════
#  2. Fix #13: VPC FLOW LOGS — Full network forensics
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs_role.arn

  tags = { Name = "${local.prefix}-vpc-flow-logs" }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/cloudfreeze/vpc-flow-logs"
  retention_in_days = 30
  tags              = { Name = "${local.prefix}-flow-logs" }
}

resource "aws_iam_role" "flow_logs_role" {
  name = "${local.prefix}-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
  tags = { Name = "${local.prefix}-flow-logs-role" }
}

resource "aws_iam_role_policy" "flow_logs_policy" {
  name = "${local.prefix}-flow-logs-policy"
  role = aws_iam_role.flow_logs_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}


# ══════════════════════════════════════════════════════════════════════════════
#  3. EC2 TEST INSTANCE + IAM ROLE (Fix #11: SSM, no SSH keys)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_role" "ec2_role" {
  name = "${local.prefix}-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = { Name = "${local.prefix}-ec2-role" }
}

# EC2 permissions: S3 read + KMS encrypt (for testing tripwires)
resource "aws_iam_role_policy" "ec2_permissions" {
  name = "${local.prefix}-ec2-policy"
  role = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowS3Read"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.honeytoken.arn, "${aws_s3_bucket.honeytoken.arn}/*"]
      },
      {
        Sid      = "AllowKMSEncrypt"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource = "*"
      },
      {
        Sid      = "AllowLambdaInvoke"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = [aws_lambda_function.killswitch.arn]
      },
      {
        Sid      = "v5Heartbeat"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "CloudFreeze/Agent" }
        }
      },
      {
        Sid      = "v5SSMCanaryChecksums"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/cloudfreeze/*"
      }
    ]
  })
}

# Fix #11: SSM Session Manager access (no SSH keys needed)
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${local.prefix}-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# Fix #8: Enable EBS encryption by default at account level
resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

resource "aws_instance" "target" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.normal.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # No key_name — use SSM Session Manager instead (Fix #11)

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true    # Fix #8: Encrypted root volume
  }

  # Install CloudWatch Agent + v4 real-time instance monitor + canary files
  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    # ── CloudWatch Agent (kept for dashboard metrics) ──
    yum install -y amazon-cloudwatch-agent jq
    cat > /opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent-config.json << 'CONFIG'
    {
      "metrics": {
        "namespace": "CloudFreeze/EC2",
        "metrics_collected": {
          "disk": {
            "measurement": ["disk_used_percent", "disk_free"],
            "metrics_collection_interval": 10,
            "resources": ["*"]
          },
          "cpu": {
            "measurement": ["cpu_usage_active"],
            "metrics_collection_interval": 10,
            "totalcpu": true
          },
          "diskio": {
            "measurement": ["write_bytes", "write_time", "io_time"],
            "metrics_collection_interval": 10,
            "resources": ["*"]
          }
        },
        "append_dimensions": {
          "InstanceId": "$${aws:InstanceId}"
        }
      }
    }
    CONFIG
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config \
      -m ec2 \
      -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent-config.json \
      -s

    # ── v4 REAL-TIME: Create canary tripwire files ──
    mkdir -p /var/cloudfreeze/canary
    echo "PRODUCTION_DB_BACKUP_2026_DO_NOT_DELETE" > /var/cloudfreeze/canary/db_backup_latest.sql
    echo "CONFIDENTIAL_FINANCIAL_RECORDS_Q1_2026" > /var/cloudfreeze/canary/financial_records.xlsx
    echo "EMPLOYEE_SSN_RECORDS_INTERNAL_ONLY" > /var/cloudfreeze/canary/employee_data.csv
    echo "BACKUP_ENCRYPTION_KEYS_MASTER" > /var/cloudfreeze/canary/master_keys.pem
    echo "CUSTOMER_PII_DATABASE_EXPORT" > /var/cloudfreeze/canary/customer_pii.json
    # Record original checksums for tamper detection
    sha256sum /var/cloudfreeze/canary/* > /var/cloudfreeze/canary/.checksums
    chmod 444 /var/cloudfreeze/canary/.checksums

    # v7 Fix #14: Push checksums to SSM Parameter Store (tamper-proof)
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    aws ssm put-parameter \
      --name "/cloudfreeze/canary-checksums" \
      --value "$(cat /var/cloudfreeze/canary/.checksums)" \
      --type SecureString \
      --overwrite \
      --region "$REGION" 2>/dev/null || true

    # ── v7 REAL-TIME: Install monitoring agent at boot (0s gap) ──
    # This ensures new instances are monitored from first boot, eliminating
    # the 4-hour SSM association cron gap.
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    LAMBDA_NAME="${aws_lambda_function.killswitch.function_name}"
    CPU_THRESHOLD="${var.cpu_threshold}"
    DISK_WRITE_THRESHOLD_MB="50"
    CHECK_INTERVAL="5"

    mkdir -p /opt/cloudfreeze
    cat > /opt/cloudfreeze/monitor.sh << 'MONITOR_SCRIPT'
    #!/bin/bash
    set -uo pipefail
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    LOG_FILE=/var/log/cloudfreeze-monitor.log
    CANARY_DIR=/var/cloudfreeze/canary
    LOCK_FILE=/tmp/cloudfreeze-alert-sent
    COOLDOWN=300
    HEARTBEAT_INTERVAL=60
    HEARTBEAT_COUNTER=0

    log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [CloudFreeze] $1" >> "$LOG_FILE"; }

    invoke_lambda() {
      local alert_type=$1
      local detail=$2
      if [ -f "$LOCK_FILE" ]; then
        local lock_age=$(( $(date +%s) - $(stat -c %Y "$LOCK_FILE") ))
        if [ "$lock_age" -lt "$COOLDOWN" ]; then
          log "Alert cooldown active ($${lock_age}s/$${COOLDOWN}s), skipping"
          return
        fi
      fi
      touch "$LOCK_FILE"
      local payload=$(printf '{"source":"instance-agent","instance_id":"%s","alert_type":"%s","detail":"%s","timestamp":"%s"}' "$INSTANCE_ID" "$alert_type" "$detail" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')")
      log "ALERT: $alert_type — invoking Lambda: $payload"
      aws lambda invoke --function-name "$LAMBDA_NAME" --region "$REGION" --payload "$payload" --cli-binary-format raw-in-base64-out /tmp/cloudfreeze-response.json >> "$LOG_FILE" 2>&1 || true
    }

    check_cpu() {
      local cpu_idle=$(top -bn1 | grep 'Cpu(s)' | awk '{print $8}' | cut -d'.' -f1)
      local cpu_used=$((100 - $${cpu_idle:-100}))
      if [ "$cpu_used" -ge "$CPU_THRESHOLD" ]; then
        invoke_lambda 'cpu-spike' "CPU at $${cpu_used}% (threshold: $${CPU_THRESHOLD}%)"
      fi
    }

    check_disk_io() {
      local write_kb_before=$(cat /proc/diskstats | awk '{sum+=$10} END{print sum}')
      sleep 1
      local write_kb_after=$(cat /proc/diskstats | awk '{sum+=$10} END{print sum}')
      local write_mb=$(( (write_kb_after - write_kb_before) / 2048 ))
      if [ "$write_mb" -ge "$DISK_WRITE_THRESHOLD_MB" ]; then
        invoke_lambda 'disk-spike' "Disk write $${write_mb}MB/s (threshold: $${DISK_WRITE_THRESHOLD_MB}MB)"
      fi
    }

    check_canary() {
      if [ ! -d "$CANARY_DIR" ]; then return; fi
      local ssm_checksums=$(aws ssm get-parameter --name '/cloudfreeze/canary-checksums' --region "$REGION" --query 'Parameter.Value' --output text 2>/dev/null || echo '')
      if [ -z "$ssm_checksums" ]; then
        if [ ! -f "$CANARY_DIR/.checksums" ]; then return; fi
        ssm_checksums=$(cat "$CANARY_DIR/.checksums")
      fi
      local expected_count=$(echo "$ssm_checksums" | wc -l)
      local actual_count=$(find "$CANARY_DIR" -maxdepth 1 -type f ! -name '.checksums' | wc -l)
      if [ "$actual_count" -lt "$expected_count" ]; then
        invoke_lambda 'canary-deleted' "Canary files deleted: expected $expected_count, found $actual_count"
        return
      fi
      if ! echo "$ssm_checksums" | sha256sum --check --quiet 2>/dev/null; then
        invoke_lambda 'canary-tampered' "Canary file checksum mismatch"
      fi
    }

    send_heartbeat() {
      aws cloudwatch put-metric-data \
        --namespace 'CloudFreeze/Agent' \
        --metric-name 'Heartbeat' \
        --value 1 \
        --dimensions InstanceId=$INSTANCE_ID \
        --region "$REGION" 2>/dev/null || true
    }

    log "CloudFreeze v7 monitoring agent started"
    send_heartbeat
    while true; do
      check_canary
      check_cpu
      check_disk_io
      HEARTBEAT_COUNTER=$((HEARTBEAT_COUNTER + CHECK_INTERVAL))
      if [ "$HEARTBEAT_COUNTER" -ge "$HEARTBEAT_INTERVAL" ]; then
        send_heartbeat
        HEARTBEAT_COUNTER=0
      fi
      sleep "$CHECK_INTERVAL"
    done
    MONITOR_SCRIPT

    # Fix variable references in the agent script
    sed -i "s|\$LAMBDA_NAME|$LAMBDA_NAME|g" /opt/cloudfreeze/monitor.sh
    sed -i "s|\$CPU_THRESHOLD|$CPU_THRESHOLD|g" /opt/cloudfreeze/monitor.sh
    sed -i "s|\$DISK_WRITE_THRESHOLD_MB|$DISK_WRITE_THRESHOLD_MB|g" /opt/cloudfreeze/monitor.sh
    sed -i "s|\$CHECK_INTERVAL|$CHECK_INTERVAL|g" /opt/cloudfreeze/monitor.sh
    chmod +x /opt/cloudfreeze/monitor.sh

    # Install as systemd service with auto-restart
    cat > /etc/systemd/system/cloudfreeze-monitor.service << 'SYSTEMD_UNIT'
    [Unit]
    Description=CloudFreeze v7 Real-Time Monitoring Agent
    After=network.target amazon-ssm-agent.service
    Wants=network.target

    [Service]
    Type=simple
    ExecStart=/opt/cloudfreeze/monitor.sh
    Restart=always
    RestartSec=5
    WatchdogSec=120
    ProtectSystem=strict
    ReadWritePaths=/var/log /tmp /var/cloudfreeze
    StandardOutput=append:/var/log/cloudfreeze-monitor.log
    StandardError=append:/var/log/cloudfreeze-monitor.log

    [Install]
    WantedBy=multi-user.target
    SYSTEMD_UNIT

    systemctl daemon-reload
    systemctl enable --now cloudfreeze-monitor.service

    # Make the monitor script immutable to prevent attacker tampering
    chattr +i /opt/cloudfreeze/monitor.sh || true
    echo 'CloudFreeze v7 monitoring agent installed and running'
  EOF
  )

  tags = {
    Name        = "${local.prefix}-target-instance"
    CloudFreeze = "monitored"     # Fix #2: tag-based discovery
  }

  depends_on = [aws_ebs_encryption_by_default.enabled]
}


# ══════════════════════════════════════════════════════════════════════════════
#  4. S3 HONEYTOKEN BUCKET + DECOY + S3 EVENT NOTIFICATION (Fix #4)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_s3_bucket" "honeytoken" {
  bucket        = "${local.prefix}-honeytoken-${local.account_id}"
  # v7 Fix 10: Removed force_destroy — audit/security buckets must be protected
  force_destroy = false
  tags = {
    Name        = "${local.prefix}-honeytoken-bucket"
    CloudFreeze = "honeytoken"
  }
}

resource "aws_s3_bucket_versioning" "honeytoken" {
  bucket = aws_s3_bucket.honeytoken.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "honeytoken" {
  bucket                  = aws_s3_bucket.honeytoken.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "decoy_file" {
  bucket  = aws_s3_bucket.honeytoken.id
  key     = "honeytokens/000_database_passwords.csv"
  content = <<-CSV
    hostname,username,password,database,port
    prod-db-master.internal,admin,P@ssw0rd_DECOY_ALERT,production,5432
    prod-db-replica.internal,readonly,R3ad0nly_DECOY_ALERT,production,5432
    staging-db.internal,stg_admin,Stag1ng_DECOY_ALERT,staging,5432
  CSV
  tags = {
    CloudFreeze = "honeytoken-decoy"
    WARNING     = "ACCESS_TRIGGERS_LOCKDOWN"
  }
}

# Fix #4: S3 Event Notification → Lambda (sub-second, bypasses CloudTrail)
resource "aws_lambda_permission" "s3_invoke_killswitch" {
  statement_id  = "AllowS3InvokeKillswitch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.honeytoken.arn
}

resource "aws_s3_bucket_notification" "honeytoken_notification" {
  bucket = aws_s3_bucket.honeytoken.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.killswitch.arn
    events              = ["s3:ObjectAccessed:*", "s3:ObjectCreated:*"]
    filter_prefix       = "honeytokens/"
    filter_suffix       = ".csv"
  }

  depends_on = [aws_lambda_permission.s3_invoke_killswitch]
}


# ══════════════════════════════════════════════════════════════════════════════
#  5. CLOUDTRAIL — Management Events + S3 Data Events
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${local.prefix}-cloudtrail-logs-${local.account_id}"
  # v7 Fix 10: Removed force_destroy — audit logs must be preserved
  force_destroy = false
  tags          = { Name = "${local.prefix}-cloudtrail-logs" }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.prefix}-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.prefix}-trail"
          }
        }
      }
    ]
  })
}

# CloudWatch Log Group for CloudTrail (enables metric filters for Fix #1)
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudfreeze/cloudtrail"
  retention_in_days = 30
  tags              = { Name = "${local.prefix}-cloudtrail-logs" }
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${local.prefix}-cloudtrail-cw-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "${local.prefix}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true   # v7 Fix #1: Multi-region detection
  enable_logging                = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.honeytoken.arn}/"]
    }
  }

  tags       = { Name = "${local.prefix}-cloudtrail" }
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}


# ══════════════════════════════════════════════════════════════════════════════
#  6. Fix #1: KMS RATE-BASED DETECTION
# ══════════════════════════════════════════════════════════════════════════════
# v4 REAL-TIME UPGRADE: Primary detection is now IN-LAMBDA via DynamoDB atomic
# counters (10-30s latency via EventBridge). The CloudWatch metric filter +
# alarm below are kept as DASHBOARD/BACKUP metrics only — they no longer
# drive the quarantine decision.

# DASHBOARD/BACKUP ONLY — real-time detection is in Lambda via DynamoDB counters
resource "aws_cloudwatch_log_metric_filter" "kms_encrypt_count" {
  name           = "${local.prefix}-kms-encrypt-count"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  pattern = "{ ($.eventSource = \"kms.amazonaws.com\") && ($.eventName = \"Encrypt\" || $.eventName = \"Decrypt\" || $.eventName = \"GenerateDataKey\") }"

  metric_transformation {
    name          = "KMSEncryptCallCount"
    namespace     = "CloudFreeze/KMS"
    value         = "1"
    default_value = "0"
  }
}

# DASHBOARD/BACKUP ONLY — kept for CloudWatch dashboard visibility
resource "aws_cloudwatch_metric_alarm" "kms_rate_alarm" {
  alarm_name          = "${local.prefix}-kms-rate-spike"
  alarm_description   = "CloudFreeze: KMS rate dashboard metric (backup — real-time is in-Lambda)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "KMSEncryptCallCount"
  namespace           = "CloudFreeze/KMS"
  period              = 60
  statistic           = "Sum"
  threshold           = var.kms_call_threshold
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
  tags          = { Name = "${local.prefix}-kms-rate-alarm" }
}


# ══════════════════════════════════════════════════════════════════════════════
#  7. Fix #5: DYNAMODB IDEMPOTENCY TABLE
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_dynamodb_table" "incidents" {
  name         = "${local.prefix}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "target_id"

  attribute {
    name = "target_id"
    type = "S"
  }

  # TTL: incident records auto-expire after 24 hours
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name        = "${local.prefix}-incidents"
    CloudFreeze = "idempotency"
  }

  # v7 Fix: Encrypt incident records at rest
  server_side_encryption {
    enabled = true
  }
}

# v4 REAL-TIME: DynamoDB table for in-Lambda KMS rate counting
# Each item = 1-minute window counter, auto-expires via TTL
resource "aws_dynamodb_table" "kms_rate" {
  name         = "${local.prefix}-kms-rate"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "window_key"

  attribute {
    name = "window_key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name        = "${local.prefix}-kms-rate"
    CloudFreeze = "realtime-rate-counter"
  }

  # v7 Fix: Encrypt rate counter data at rest
  server_side_encryption {
    enabled = true
  }
}


# ══════════════════════════════════════════════════════════════════════════════
#  8. Fix #8: KMS KEY FOR FORENSIC SNAPSHOT ENCRYPTION
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_kms_key" "forensic" {
  description             = "CloudFreeze forensic snapshot encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = { Name = "${local.prefix}-forensic-key" }
}

resource "aws_kms_alias" "forensic" {
  name          = "alias/${local.prefix}-forensic-key"
  target_key_id = aws_kms_key.forensic.key_id
}


# ══════════════════════════════════════════════════════════════════════════════
#  9. SNS NOTIFICATION TOPIC
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_sns_topic" "alerts" {
  name = "${local.prefix}-alerts"
  tags = { Name = "${local.prefix}-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}


# ══════════════════════════════════════════════════════════════════════════════
#  10. LAMBDA KILL-SWITCH (upgraded with all fixes)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_role" "lambda_role" {
  name = "${local.prefix}-lambda-killswitch-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = { Name = "${local.prefix}-lambda-role" }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Comprehensive least-privilege policy for all takedown actions
resource "aws_iam_role_policy" "lambda_killswitch_policy" {
  name = "${local.prefix}-lambda-killswitch-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "NetworkQuarantine"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:ModifyNetworkInterfaceAttribute"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRevocationEC2"
        Effect = "Allow"
        Action = [
          "ec2:DescribeIamInstanceProfileAssociations",
          "ec2:DisassociateIamInstanceProfile"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRevocationIdentity"
        Effect = "Allow"
        Action = [
          "iam:PutUserPolicy",
          "iam:PutRolePolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "ForensicPreservation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVolumes",
          "ec2:CreateSnapshot",
          "ec2:CopySnapshot",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid      = "ForensicEncryption"
        Effect   = "Allow"
        Action   = ["kms:CreateGrant", "kms:DescribeKey"]
        Resource = [aws_kms_key.forensic.arn]
      },
      {
        Sid      = "SNSNotify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.alerts.arn]
      },
      {
        Sid    = "DynamoDBIdempotency"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = [aws_dynamodb_table.incidents.arn]
      }
    ]
  })
}

# Fix #15: DLQ for Kill-Switch Lambda
resource "aws_sqs_queue" "killswitch_dlq" {
  name                      = "${local.prefix}-killswitch-dlq"
  message_retention_seconds = 1209600  # 14 days
  tags                      = { Name = "${local.prefix}-killswitch-dlq" }
}

resource "aws_lambda_function" "killswitch" {
  function_name    = "${local.prefix}-killswitch"
  description      = "CloudFreeze v7 Kill-Switch: Zero-Failure Quarantine + Per-IP NACL + IAM Revoke + Circuit Breaker + Async Forensics"
  filename         = "${path.module}/lambda/lambda_function.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/lambda_function.zip")
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60   # v7: Reduced from 120s — forensics runs async now
  memory_size      = 256
  role             = aws_iam_role.lambda_role.arn

  # v7 Fix I: Reserved concurrency — guarantees kill-switch capacity
  reserved_concurrent_executions = 50

  # Fix #15: Dead-Letter Queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.killswitch_dlq.arn
  }

  environment {
    variables = {
      QUARANTINE_SG_ID     = aws_security_group.quarantine.id
      NORMAL_SG_ID         = aws_security_group.normal.id
      SNS_TOPIC_ARN        = aws_sns_topic.alerts.arn
      DYNAMODB_TABLE       = aws_dynamodb_table.incidents.name
      SNAPSHOT_KMS_KEY_ARN = aws_kms_key.forensic.arn
      # v4 REAL-TIME: In-Lambda KMS rate counter
      KMS_RATE_TABLE       = aws_dynamodb_table.kms_rate.name
      KMS_RATE_THRESHOLD   = tostring(var.kms_call_threshold)
      KMS_RATE_WINDOW      = "60"
      # v7: Async forensic Lambda + NACL quarantine
      FORENSIC_LAMBDA_ARN  = aws_lambda_function.forensic.arn
      QUARANTINE_NACL_ID   = aws_network_acl.quarantine.id
    }
  }

  tags = {
    Name        = "${local.prefix}-killswitch"
    CloudFreeze = "kill-switch"
  }
}

# Fix #17: Provisioned concurrency — eliminates cold starts for instant response
resource "aws_lambda_alias" "killswitch_live" {
  name             = "live"
  function_name    = aws_lambda_function.killswitch.function_name
  function_version = aws_lambda_function.killswitch.version
}

resource "aws_lambda_provisioned_concurrency_config" "killswitch" {
  function_name                  = aws_lambda_function.killswitch.function_name
  provisioned_concurrent_executions = 1
  qualifier                      = aws_lambda_alias.killswitch_live.name
}


# ══════════════════════════════════════════════════════════════════════════════
#  11. Fix #6: RESTORE LAMBDA (un-quarantine)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_role" "lambda_restore_role" {
  name = "${local.prefix}-lambda-restore-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = { Name = "${local.prefix}-lambda-restore-role" }
}

resource "aws_iam_role_policy_attachment" "lambda_restore_basic" {
  role       = aws_iam_role.lambda_restore_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_restore_policy" {
  name = "${local.prefix}-lambda-restore-policy"
  role = aws_iam_role.lambda_restore_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestoreNetworkAndIAM"
        Effect = "Allow"
        Action = [
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:AssociateIamInstanceProfile",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      },
      {
        Sid    = "RestoreIAMPolicies"
        Effect = "Allow"
        Action = [
          "iam:DeleteUserPolicy",
          "iam:DeleteRolePolicy"
        ]
        Resource = "*"
      },
      {
        Sid      = "DynamoDB"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.incidents.arn]
      },
      {
        Sid      = "SNSNotify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.alerts.arn]
      }
    ]
  })
}

# Fix #15: DLQ for Restore Lambda
resource "aws_sqs_queue" "restore_dlq" {
  name                      = "${local.prefix}-restore-dlq"
  message_retention_seconds = 1209600  # 14 days
  tags                      = { Name = "${local.prefix}-restore-dlq" }
}

resource "aws_lambda_function" "restore" {
  function_name    = "${local.prefix}-restore"
  description      = "CloudFreeze v3 Restore: Un-quarantine with edge-case handling"
  filename         = "${path.module}/lambda/lambda_restore.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/lambda_restore.zip")
  handler          = "lambda_restore.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  role             = aws_iam_role.lambda_restore_role.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.restore_dlq.arn
  }

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.incidents.name
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
    }
  }

  tags = {
    Name        = "${local.prefix}-restore"
    CloudFreeze = "restore"
  }
}


# ══════════════════════════════════════════════════════════════════════════════
#  11b. v7 FORENSIC LAMBDA (async snapshot + memory capture)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_role" "lambda_forensic_role" {
  name = "${local.prefix}-lambda-forensic-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = { Name = "${local.prefix}-lambda-forensic-role" }
}

resource "aws_iam_role_policy_attachment" "lambda_forensic_basic" {
  role       = aws_iam_role.lambda_forensic_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_forensic_policy" {
  name = "${local.prefix}-lambda-forensic-policy"
  role = aws_iam_role.lambda_forensic_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ForensicSnapshots"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVolumes",
          "ec2:CreateSnapshot",
          "ec2:CopySnapshot",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid      = "ForensicEncryption"
        Effect   = "Allow"
        Action   = ["kms:CreateGrant", "kms:DescribeKey"]
        Resource = [aws_kms_key.forensic.arn]
      },
      {
        Sid      = "SNSNotify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.alerts.arn]
      },
      {
        Sid    = "MemoryForensicsSSM"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation"
        ]
        Resource = "*"
      },
      {
        Sid    = "ForensicS3Upload"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.forensic_data.arn}/*"]
      }
    ]
  })
}

# v7: S3 bucket for memory forensic data
resource "aws_s3_bucket" "forensic_data" {
  bucket        = "${local.prefix}-forensic-data-${local.account_id}"
  # v7 Fix 10: Keep force_destroy only for forensic data (easy cleanup)
  force_destroy = true
  tags          = { Name = "${local.prefix}-forensic-data" }
}

resource "aws_s3_bucket_public_access_block" "forensic_data" {
  bucket                  = aws_s3_bucket.forensic_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# v7 Fix 22: Enforce server-side encryption on forensic data bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "forensic_data" {
  bucket = aws_s3_bucket.forensic_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.forensic.id
    }
  }
}

# v7 Fix 12: S3 lifecycle rules for forensic data
resource "aws_s3_bucket_lifecycle_configuration" "forensic_data" {
  bucket = aws_s3_bucket.forensic_data.id
  rule {
    id     = "archive-old-forensic-data"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
    expiration {
      days = 365
    }
  }
}

# v7 Fix 12: S3 lifecycle rules for CloudTrail logs
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    id     = "archive-old-cloudtrail-logs"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration {
      days = 730
    }
  }
}

resource "aws_sqs_queue" "forensic_dlq" {
  name                      = "${local.prefix}-forensic-dlq"
  message_retention_seconds = 1209600
  tags                      = { Name = "${local.prefix}-forensic-dlq" }
}

resource "aws_lambda_function" "forensic" {
  function_name    = "${local.prefix}-forensic"
  description      = "CloudFreeze v7 Forensic: Async EBS snapshots + memory capture"
  filename         = "${path.module}/lambda/lambda_forensic.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/lambda_forensic.zip")
  handler          = "lambda_forensic.lambda_handler"
  runtime          = "python3.12"
  timeout          = 300   # v7: 5 minutes for slow snapshot operations
  memory_size      = 256
  role             = aws_iam_role.lambda_forensic_role.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.forensic_dlq.arn
  }

  environment {
    variables = {
      FORENSIC_S3_BUCKET       = aws_s3_bucket.forensic_data.id
      ENABLE_MEMORY_FORENSICS  = tostring(var.enable_memory_forensics)
    }
  }

  tags = {
    Name        = "${local.prefix}-forensic"
    CloudFreeze = "forensic"
  }
}

resource "aws_iam_role_policy" "lambda_forensic_dlq" {
  name = "${local.prefix}-lambda-forensic-dlq"
  role = aws_iam_role.lambda_forensic_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DLQSendMessage"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [aws_sqs_queue.forensic_dlq.arn]
    }]
  })
}


# ══════════════════════════════════════════════════════════════════════════════
#  12. EVENTBRIDGE RULES — All Tripwires → Lambda Permissions
# ══════════════════════════════════════════════════════════════════════════════

# ── Lambda Permissions for EventBridge ───────────────────────────────────────

resource "aws_lambda_permission" "eventbridge_kms" {
  statement_id  = "AllowEventBridgeKMS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.kms_tripwire.arn
}

resource "aws_lambda_permission" "eventbridge_honeytoken" {
  statement_id  = "AllowEventBridgeHoneytoken"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.honeytoken_tripwire.arn
}

resource "aws_lambda_permission" "eventbridge_velocity" {
  statement_id  = "AllowEventBridgeVelocity"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.velocity_tripwire.arn
}

resource "aws_lambda_permission" "eventbridge_kms_foreign" {
  statement_id  = "AllowEventBridgeKMSForeign"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.kms_foreign_key_tripwire.arn
}

resource "aws_lambda_permission" "eventbridge_kms_rate" {
  statement_id  = "AllowEventBridgeKMSRate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.kms_rate_tripwire.arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  13. TRIPWIRE 1 — KMS CRYPTOGRAPHIC TRAP
# ══════════════════════════════════════════════════════════════════════════════

# v4 REAL-TIME: This rule is now the PRIMARY KMS detection path.
# EventBridge delivers CloudTrail events in 10-30 seconds (NOT 5-15 min).
# The Lambda performs in-Lambda rate counting via DynamoDB atomic counters.
# This is 10x faster than the old CloudWatch metric filter → alarm pipeline.
resource "aws_cloudwatch_event_rule" "kms_tripwire" {
  name        = "${local.prefix}-kms-tripwire"
  description = "v4 REAL-TIME PRIMARY: KMS calls → Lambda with in-Lambda rate counting (10-30s)"

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["Encrypt", "Decrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext"]
      userIdentity = {
        type = ["AssumedRole"]
        sessionContext = {
          sessionIssuer = {
            arn = [aws_iam_role.ec2_role.arn]
          }
        }
      }
    }
  })

  # v4: ENABLED — this is now the primary real-time KMS detection path
  state = "ENABLED"

  tags = { Name = "${local.prefix}-kms-tripwire" }
}

resource "aws_cloudwatch_event_target" "kms_to_lambda" {
  rule      = aws_cloudwatch_event_rule.kms_tripwire.name
  target_id = "KMSTripwireToLambda"
  arn       = aws_lambda_function.killswitch.arn
}

# KMS Rate-Based Tripwire: EventBridge catches the CloudWatch Alarm state change
resource "aws_cloudwatch_event_rule" "kms_rate_tripwire" {
  name        = "${local.prefix}-kms-rate-tripwire"
  description = "Tripwire 1 (Fix #1): KMS call rate spike alarm → Lambda kill-switch"

  event_pattern = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = ["${local.prefix}-kms-rate-spike"]
      state     = { value = ["ALARM"] }
    }
  })

  tags = { Name = "${local.prefix}-kms-rate-tripwire" }
}

resource "aws_cloudwatch_event_target" "kms_rate_to_lambda" {
  rule      = aws_cloudwatch_event_rule.kms_rate_tripwire.name
  target_id = "KMSRateTripwireToLambda"
  arn       = aws_lambda_function.killswitch.arn
}

# Cross-account KMS key detection
resource "aws_cloudwatch_event_rule" "kms_foreign_key_tripwire" {
  name        = "${local.prefix}-kms-foreign-key-tripwire"
  description = "Tripwire 1b: Cross-account KMS key hijack attempts"

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["Encrypt", "Decrypt", "GenerateDataKey"]
      errorCode   = ["AccessDeniedException", "KMSInvalidStateException"]
    }
  })

  tags = { Name = "${local.prefix}-kms-foreign-key-tripwire" }
}

resource "aws_cloudwatch_event_target" "kms_foreign_to_lambda" {
  rule      = aws_cloudwatch_event_rule.kms_foreign_key_tripwire.name
  target_id = "KMSForeignKeyToLambda"
  arn       = aws_lambda_function.killswitch.arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  14. TRIPWIRE 2 — HONEYTOKEN BAIT TRAP (EventBridge — secondary)
# ══════════════════════════════════════════════════════════════════════════════
# Fix #4: The PRIMARY honeytoken detection is now the S3 Event Notification
# (section 4) which fires in sub-seconds. This EventBridge rule is a
# SECONDARY layer via CloudTrail for additional context and logging.

resource "aws_cloudwatch_event_rule" "honeytoken_tripwire" {
  name        = "${local.prefix}-honeytoken-tripwire"
  description = "Tripwire 2 (secondary): CloudTrail-based honeytoken access detection"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject", "PutObject", "HeadObject"]
      requestParameters = {
        bucketName = [aws_s3_bucket.honeytoken.id]
        key        = ["honeytokens/000_database_passwords.csv"]
      }
    }
  })

  tags = { Name = "${local.prefix}-honeytoken-tripwire" }
}

resource "aws_cloudwatch_event_target" "honeytoken_to_lambda" {
  rule      = aws_cloudwatch_event_rule.honeytoken_tripwire.name
  target_id = "HoneytokenTripwireToLambda"
  arn       = aws_lambda_function.killswitch.arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  15. TRIPWIRE 3 — VELOCITY SPEED TRAP (CloudWatch Alarm → EventBridge)
# ══════════════════════════════════════════════════════════════════════════════

# Standard EC2 metric alarm: Disk Write Operations spike
resource "aws_cloudwatch_metric_alarm" "disk_write_spike" {
  alarm_name          = "${local.prefix}-disk-write-spike"
  alarm_description   = "Velocity Tripwire: Disk write operations spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DiskWriteOps"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Sum"
  threshold           = var.disk_write_threshold
  treat_missing_data  = "notBreaching"
  dimensions          = { InstanceId = aws_instance.target.id }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-disk-write-alarm" }
}

# Standard EC2 metric alarm: CPU spike (BYO-Crypto detection)
resource "aws_cloudwatch_metric_alarm" "cpu_spike" {
  alarm_name          = "${local.prefix}-cpu-spike"
  alarm_description   = "Velocity Tripwire: CPU utilization spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = var.cpu_threshold
  treat_missing_data  = "notBreaching"
  dimensions          = { InstanceId = aws_instance.target.id }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-cpu-spike-alarm" }
}

# High-resolution custom metric alarm (from CloudWatch Agent — 10-second intervals)
resource "aws_cloudwatch_metric_alarm" "disk_io_spike" {
  alarm_name          = "${local.prefix}-diskio-write-bytes-spike"
  alarm_description   = "Velocity Tripwire: High-res disk I/O write bytes spike (10s granularity)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3                      # 3 × 10s = 30 seconds sustained
  metric_name         = "diskio_write_bytes"
  namespace           = "CloudFreeze/EC2"
  period              = 10                     # 10-second high-resolution period
  statistic           = "Sum"
  threshold           = 104857600              # 100 MB in 10 seconds
  treat_missing_data  = "notBreaching"
  dimensions          = { InstanceId = aws_instance.target.id }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-diskio-alarm" }
}

# EventBridge rule: catch ALL velocity alarm state changes → Lambda
resource "aws_cloudwatch_event_rule" "velocity_tripwire" {
  name        = "${local.prefix}-velocity-tripwire"
  description = "Tripwire 3: Routes CloudWatch alarm state changes to Lambda"

  event_pattern = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = [
        "${local.prefix}-disk-write-spike",
        "${local.prefix}-cpu-spike",
        "${local.prefix}-diskio-write-bytes-spike"
      ]
      state = { value = ["ALARM"] }
    }
  })

  tags = { Name = "${local.prefix}-velocity-tripwire" }
}

resource "aws_cloudwatch_event_target" "velocity_to_lambda" {
  rule      = aws_cloudwatch_event_rule.velocity_tripwire.name
  target_id = "VelocityTripwireToLambda"
  arn       = aws_lambda_function.killswitch.arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  16. Fix #14: GUARDDUTY — ML-Based Real-Time Threat Detection
# ══════════════════════════════════════════════════════════════════════════════
# GuardDuty uses ML + threat intelligence to detect threats in REAL-TIME.
# Detection latency: seconds (vs CloudTrail: 5–15 minutes).
# Catches: crypto-mining, reconnaissance, unauthorized access, trojans.

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    s3_logs      { enable = true }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }

  tags = { Name = "${local.prefix}-guardduty" }
}

# EventBridge rule: GuardDuty high-severity findings → Lambda
resource "aws_cloudwatch_event_rule" "guardduty_tripwire" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "${local.prefix}-guardduty-tripwire"
  description = "Fix #14: Routes GuardDuty findings to Lambda kill-switch"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]
    }
  })

  tags = { Name = "${local.prefix}-guardduty-tripwire" }
}

resource "aws_cloudwatch_event_target" "guardduty_to_lambda" {
  count     = var.enable_guardduty ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_tripwire[0].name
  target_id = "GuardDutyToLambda"
  arn       = aws_lambda_function.killswitch.arn
}

resource "aws_lambda_permission" "eventbridge_guardduty" {
  count         = var.enable_guardduty ? 1 : 0
  statement_id  = "AllowEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_tripwire[0].arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  17. Fix #15: SQS DLQ IAM Permissions for Lambda
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_role_policy" "lambda_dlq_policy" {
  name = "${local.prefix}-lambda-dlq-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DLQSendMessage"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [aws_sqs_queue.killswitch_dlq.arn]
    }]
  })
}

resource "aws_iam_role_policy" "lambda_restore_dlq_policy" {
  name = "${local.prefix}-lambda-restore-dlq-policy"
  role = aws_iam_role.lambda_restore_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DLQSendMessage"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [aws_sqs_queue.restore_dlq.arn]
    }]
  })
}

# EC2 DescribeInstances is needed for tag-based instance discovery
resource "aws_iam_role_policy" "lambda_ec2_describe" {
  name = "${local.prefix}-lambda-ec2-describe"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DescribeSecurityGroups"
      Effect   = "Allow"
      Action   = ["ec2:DescribeSecurityGroups"]
      Resource = "*"
    }]
  })
}

# v4 REAL-TIME: Lambda permission for KMS rate counter DynamoDB table
resource "aws_iam_role_policy" "lambda_kms_rate_policy" {
  name = "${local.prefix}-lambda-kms-rate-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "KMSRateCounter"
      Effect   = "Allow"
      Action   = ["dynamodb:UpdateItem", "dynamodb:GetItem"]
      Resource = [aws_dynamodb_table.kms_rate.arn]
    }]
  })
}

# v4 REAL-TIME: Lambda permission for EC2 instance agent invocation
resource "aws_lambda_permission" "ec2_agent_invoke" {
  statement_id  = "AllowEC2AgentInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "arn:aws:iam::${local.account_id}:root"
}

# v7: Lambda permission to invoke forensic Lambda
resource "aws_iam_role_policy" "lambda_invoke_forensic" {
  name = "${local.prefix}-lambda-invoke-forensic"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeForensicLambda"
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = [aws_lambda_function.forensic.arn]
    }]
  })
}

# v7 Fix #8: NACL management permissions for Lambda
resource "aws_iam_role_policy" "lambda_nacl_policy" {
  name = "${local.prefix}-lambda-nacl-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "NACLQuarantine"
      Effect   = "Allow"
      Action   = [
        "ec2:DescribeNetworkAcls",
        "ec2:ReplaceNetworkAclAssociation",
        # v7 Fix D: Per-IP NACL deny rules
        "ec2:CreateNetworkAclEntry",
        "ec2:DeleteNetworkAclEntry"
      ]
      Resource = "*"
    }]
  })
}

# v7 Fix B: SSM permissions for agent health checks
resource "aws_iam_role_policy" "lambda_ssm_health" {
  name = "${local.prefix}-lambda-ssm-health"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SSMHealthCheck"
      Effect   = "Allow"
      Action   = ["ssm:DescribeInstanceInformation"]
      Resource = "*"
    }]
  })
}

# v7 Fix D: Restore Lambda needs NACL entry delete permissions for per-IP restore
resource "aws_iam_role_policy" "lambda_restore_nacl" {
  name = "${local.prefix}-lambda-restore-nacl"
  role = aws_iam_role.lambda_restore_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "NACLRestore"
      Effect   = "Allow"
      Action   = [
        "ec2:DescribeNetworkAcls",
        "ec2:ReplaceNetworkAclAssociation",
        "ec2:DeleteNetworkAclEntry"
      ]
      Resource = "*"
    }]
  })
}


# ══════════════════════════════════════════════════════════════════════════════
#  20. v7 REAL-TIME: SYSTEMD MONITORING AGENT (replaces background bash)
# ══════════════════════════════════════════════════════════════════════════════
# v7 Upgrades over v4 bash background agent:
#   Fix #4:  systemd service with Restart=always (auto-restart on crash)
#   Fix #14: Canary checksums fetched from SSM Parameter Store (tamper-proof)
#   Fix #15: Time-based 5-minute cooldown lock (replaces permanent lock)
#   Fix #16: CloudWatch heartbeat metric every 60s (missing = alert)

resource "aws_ssm_document" "instance_monitor" {
  name            = "${local.prefix}-realtime-monitor"
  document_type   = "Command"
  document_format = "YAML"

  content = yamlencode({
    schemaVersion = "2.2"
    description   = "CloudFreeze v7: Systemd real-time monitor (CPU, disk, canary, heartbeat)"
    parameters = {
      LambdaFunctionName = {
        type        = "String"
        description = "Kill-Switch Lambda function name"
        default     = aws_lambda_function.killswitch.function_name
      }
      CpuThreshold = {
        type        = "String"
        description = "CPU threshold percentage"
        default     = tostring(var.cpu_threshold)
      }
      DiskWriteThresholdMB = {
        type        = "String"
        description = "Disk write MB/5s threshold"
        default     = "50"
      }
      CheckIntervalSeconds = {
        type        = "String"
        description = "Check interval in seconds"
        default     = "5"
      }
    }
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "installSystemdMonitor"
      inputs = {
        runCommand = [
          "#!/bin/bash",
          "set -euo pipefail",
          "",
          "# ── v7: Write the monitoring script to /opt/cloudfreeze/monitor.sh ──",
          "mkdir -p /opt/cloudfreeze /var/log",
          "",
          "cat > /opt/cloudfreeze/monitor.sh << 'MONITOR_SCRIPT'",
          "#!/bin/bash",
          "set -uo pipefail",
          "",
          "LAMBDA_NAME='{{LambdaFunctionName}}'",
          "CPU_THRESHOLD='{{CpuThreshold}}'",
          "DISK_WRITE_THRESHOLD_MB='{{DiskWriteThresholdMB}}'",
          "CHECK_INTERVAL='{{CheckIntervalSeconds}}'",
          "REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)",
          "INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)",
          "LOG_FILE=/var/log/cloudfreeze-monitor.log",
          "CANARY_DIR=/var/cloudfreeze/canary",
          "LOCK_FILE=/tmp/cloudfreeze-alert-sent",
          "COOLDOWN=300",
          "HEARTBEAT_INTERVAL=60",
          "HEARTBEAT_COUNTER=0",
          "",
          "log() { echo \"$(date -u '+%Y-%m-%dT%H:%M:%SZ') [CloudFreeze] $1\" >> \"$LOG_FILE\"; }",
          "",
          "# v7 Fix #15: Time-based cooldown lock (5 minutes) instead of permanent",
          "invoke_lambda() {",
          "  local alert_type=$1",
          "  local detail=$2",
          "  if [ -f \"$LOCK_FILE\" ]; then",
          "    local lock_age=$(( $(date +%s) - $(stat -c %Y \"$LOCK_FILE\") ))",
          "    if [ \"$lock_age\" -lt \"$COOLDOWN\" ]; then",
          "      log \"Alert cooldown active ($${lock_age}s/$${COOLDOWN}s), skipping\"",
          "      return",
          "    fi",
          "  fi",
          "  touch \"$LOCK_FILE\"",
          "  local payload=$(printf '{\"source\":\"instance-agent\",\"instance_id\":\"%s\",\"alert_type\":\"%s\",\"detail\":\"%s\",\"timestamp\":\"%s\"}' \"$INSTANCE_ID\" \"$alert_type\" \"$detail\" \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\")",
          "  log \"ALERT: $alert_type — invoking Lambda: $payload\"",
          "  aws lambda invoke --function-name \"$LAMBDA_NAME\" --region \"$REGION\" --payload \"$payload\" --cli-binary-format raw-in-base64-out /tmp/cloudfreeze-response.json >> \"$LOG_FILE\" 2>&1 || true",
          "}",
          "",
          "check_cpu() {",
          "  local cpu_idle=$(top -bn1 | grep 'Cpu(s)' | awk '{print $8}' | cut -d'.' -f1)",
          "  local cpu_used=$((100 - $${cpu_idle:-100}))",
          "  if [ \"$cpu_used\" -ge \"$CPU_THRESHOLD\" ]; then",
          "    invoke_lambda 'cpu-spike' \"CPU at $${cpu_used}% (threshold: $${CPU_THRESHOLD}%)\"",
          "  fi",
          "}",
          "",
          "check_disk_io() {",
          "  local write_kb_before=$(cat /proc/diskstats | awk '{sum+=$10} END{print sum}')",
          "  sleep 1",
          "  local write_kb_after=$(cat /proc/diskstats | awk '{sum+=$10} END{print sum}')",
          "  local write_mb=$(( (write_kb_after - write_kb_before) / 2048 ))",
          "  if [ \"$write_mb\" -ge \"$DISK_WRITE_THRESHOLD_MB\" ]; then",
          "    invoke_lambda 'disk-spike' \"Disk write $${write_mb}MB/s (threshold: $${DISK_WRITE_THRESHOLD_MB}MB)\"",
          "  fi",
          "}",
          "",
          "# v7 Fix #14: Fetch canary checksums from SSM Parameter Store (tamper-proof)",
          "check_canary() {",
          "  if [ ! -d \"$CANARY_DIR\" ]; then return; fi",
          "  local ssm_checksums=$(aws ssm get-parameter --name '/cloudfreeze/canary-checksums' --region \"$REGION\" --query 'Parameter.Value' --output text 2>/dev/null || echo '')",
          "  if [ -z \"$ssm_checksums\" ]; then",
          "    if [ ! -f \"$CANARY_DIR/.checksums\" ]; then return; fi",
          "    ssm_checksums=$(cat \"$CANARY_DIR/.checksums\")",
          "  fi",
          "  local expected_count=$(echo \"$ssm_checksums\" | wc -l)",
          "  local actual_count=$(find \"$CANARY_DIR\" -maxdepth 1 -type f ! -name '.checksums' | wc -l)",
          "  if [ \"$actual_count\" -lt \"$expected_count\" ]; then",
          "    invoke_lambda 'canary-deleted' \"Canary files deleted: expected $expected_count, found $actual_count\"",
          "    return",
          "  fi",
          "  if ! echo \"$ssm_checksums\" | sha256sum --check --quiet 2>/dev/null; then",
          "    invoke_lambda 'canary-tampered' \"Canary file checksum mismatch — possible encryption/modification\"",
          "  fi",
          "}",
          "",
          "# v7 Fix L: inotify-based file change rate monitoring (detects slow encryption)",
          "FILE_CHANGE_THRESHOLD=$${FILE_CHANGE_THRESHOLD:-20}",
          "FILE_CHANGE_WINDOW=60",
          "FILE_CHANGE_COUNTER=0",
          "FILE_CHANGE_LAST_RESET=$(date +%s)",
          "",
          "check_file_change_rate() {",
          "  if ! command -v inotifywait &>/dev/null; then return; fi",
          "  local now=$(date +%s)",
          "  local elapsed=$((now - FILE_CHANGE_LAST_RESET))",
          "  if [ \"$elapsed\" -ge \"$FILE_CHANGE_WINDOW\" ]; then",
          "    if [ \"$FILE_CHANGE_COUNTER\" -ge \"$FILE_CHANGE_THRESHOLD\" ]; then",
          "      invoke_lambda 'file-change-rate' \"Rapid file modifications: $${FILE_CHANGE_COUNTER} changes in $${elapsed}s (threshold: $${FILE_CHANGE_THRESHOLD}/$${FILE_CHANGE_WINDOW}s)\"",
          "    fi",
          "    FILE_CHANGE_COUNTER=0",
          "    FILE_CHANGE_LAST_RESET=$now",
          "  fi",
          "  local changes=$(timeout 2 inotifywait -r -m --format '%e' /home /var /tmp --exclude '/proc|/sys' 2>/dev/null | grep -c 'MODIFY\\|CREATE\\|DELETE' || echo 0)",
          "  FILE_CHANGE_COUNTER=$((FILE_CHANGE_COUNTER + changes))",
          "}",
          "",
          "# v7 Fix L: Shannon entropy detection (detects non-KMS local encryption)",
          "check_entropy() {",
          "  local high_entropy_count=0",
          "  local sample_files=$(find /home /var/lib -type f -name '*.enc' -o -name '*.locked' -o -name '*.crypted' -newer /tmp/cloudfreeze-entropy-marker 2>/dev/null | head -10)",
          "  touch /tmp/cloudfreeze-entropy-marker",
          "  if [ -n \"$sample_files\" ]; then",
          "    invoke_lambda 'entropy-suspicious' \"Suspicious encrypted file extensions detected: $(echo $sample_files | wc -w) files with .enc/.locked/.crypted extension\"",
          "    return",
          "  fi",
          "  for f in $(find /home -type f -size +1k -newer /tmp/cloudfreeze-entropy-marker 2>/dev/null | head -5); do",
          "    local ent=$(dd if=\"$f\" bs=4096 count=1 2>/dev/null | od -A n -t u1 | tr ' ' '\\n' | sort -n | uniq -c | awk 'BEGIN{e=0;t=0}{t+=$1}END{for(i=1;i<=NR;i++){p=$1/t;if(p>0)e-=p*log(p)/log(2)}print e}')",
          "    if [ $(echo \"$ent > 7.9\" | bc -l 2>/dev/null) -eq 1 ] 2>/dev/null; then",
          "      high_entropy_count=$((high_entropy_count + 1))",
          "    fi",
          "  done",
          "  if [ \"$high_entropy_count\" -ge 3 ]; then",
          "    invoke_lambda 'entropy-spike' \"High entropy files detected: $${high_entropy_count} files with entropy > 7.9 (likely encrypted)\"",
          "  fi",
          "}",
          "",
          "# v7: NFS/EFS mount change monitoring",
          "PREV_MOUNTS=$(mount | grep -E 'nfs|efs|cifs' | md5sum | cut -d' ' -f1)",
          "check_nfs_mounts() {",
          "  local curr_mounts=$(mount | grep -E 'nfs|efs|cifs' | md5sum | cut -d' ' -f1)",
          "  if [ \"$curr_mounts\" != \"$PREV_MOUNTS\" ]; then",
          "    invoke_lambda 'nfs-mount-change' \"NFS/EFS/CIFS mount change detected — possible attacker-controlled filesystem\"",
          "    PREV_MOUNTS=$curr_mounts",
          "  fi",
          "}",
          "",
          "# v7 Fix #16: CloudWatch heartbeat metric (missing = agent is dead)",
          "send_heartbeat() {",
          "  aws cloudwatch put-metric-data \\",
          "    --namespace 'CloudFreeze/Agent' \\",
          "    --metric-name 'Heartbeat' \\",
          "    --value 1 \\",
          "    --dimensions InstanceId=$INSTANCE_ID \\",
          "    --region \"$REGION\" 2>/dev/null || true",
          "}",
          "",
          "log \"CloudFreeze v7 systemd monitor started (CPU: $${CPU_THRESHOLD}%, Disk: $${DISK_WRITE_THRESHOLD_MB}MB, Interval: $${CHECK_INTERVAL}s, FileChangeThreshold: $${FILE_CHANGE_THRESHOLD}/min)\"",
          "send_heartbeat",
          "touch /tmp/cloudfreeze-entropy-marker",
          "",
          "ENTROPY_CHECK_COUNTER=0",
          "ENTROPY_CHECK_INTERVAL=60",
          "",
          "while true; do",
          "  check_canary",
          "  check_cpu",
          "  check_disk_io",
          "  check_file_change_rate",
          "  check_nfs_mounts",
          "",
          "  # Entropy check every ~60 seconds (more expensive)",
          "  ENTROPY_CHECK_COUNTER=$((ENTROPY_CHECK_COUNTER + CHECK_INTERVAL))",
          "  if [ \"$ENTROPY_CHECK_COUNTER\" -ge \"$ENTROPY_CHECK_INTERVAL\" ]; then",
          "    check_entropy",
          "    ENTROPY_CHECK_COUNTER=0",
          "  fi",
          "",
          "  # Heartbeat every ~60 seconds",
          "  HEARTBEAT_COUNTER=$((HEARTBEAT_COUNTER + CHECK_INTERVAL))",
          "  if [ \"$HEARTBEAT_COUNTER\" -ge \"$HEARTBEAT_INTERVAL\" ]; then",
          "    send_heartbeat",
          "    HEARTBEAT_COUNTER=0",
          "  fi",
          "",
          "  sleep \"$CHECK_INTERVAL\"",
          "done",
          "MONITOR_SCRIPT",
          "",
          "# ── v7: Install agent kill-resistance watchdog ──",
          "cat > /opt/cloudfreeze/watchdog.sh << 'WATCHDOG_SCRIPT'",
          "#!/bin/bash",
          "while true; do",
          "  if ! systemctl is-active --quiet cloudfreeze-monitor; then",
          "    logger -t CloudFreeze 'WATCHDOG: Monitor agent killed, restarting...'",
          "    systemctl restart cloudfreeze-monitor 2>/dev/null || true",
          "    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)",
          "    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)",
          "    aws cloudwatch put-metric-data --namespace 'CloudFreeze/Agent' --metric-name 'WatchdogRestart' --value 1 --dimensions InstanceId=$INSTANCE_ID --region $REGION 2>/dev/null || true",
          "  fi",
          "  chattr +i /opt/cloudfreeze/monitor.sh 2>/dev/null || true",
          "  sleep 10",
          "done",
          "WATCHDOG_SCRIPT",
          "chmod +x /opt/cloudfreeze/watchdog.sh",
          "chattr +i /opt/cloudfreeze/monitor.sh 2>/dev/null || true",
          "",
          "# ── v7 Fix #4: Install as a systemd service with auto-restart ──",
          "cat > /etc/systemd/system/cloudfreeze-monitor.service << 'SYSTEMD_UNIT'",
          "[Unit]",
          "Description=CloudFreeze v7 Real-Time Monitoring Agent",
          "After=network.target amazon-ssm-agent.service",
          "Wants=network.target",
          "",
          "[Service]",
          "Type=simple",
          "ExecStart=/opt/cloudfreeze/monitor.sh",
          "Restart=always",
          "RestartSec=5",
          "WatchdogSec=120",
          "ProtectSystem=strict",
          "ReadWritePaths=/var/log /tmp /var/cloudfreeze",
          "StandardOutput=append:/var/log/cloudfreeze-monitor.log",
          "StandardError=append:/var/log/cloudfreeze-monitor.log",
          "",
          "[Install]",
          "WantedBy=multi-user.target",
          "SYSTEMD_UNIT",
          "",
          "# v7: Watchdog service (monitors and restarts the main agent)",
          "cat > /etc/systemd/system/cloudfreeze-watchdog.service << 'WATCHDOG_UNIT'",
          "[Unit]",
          "Description=CloudFreeze v7 Agent Kill-Resistance Watchdog",
          "After=cloudfreeze-monitor.service",
          "",
          "[Service]",
          "Type=simple",
          "ExecStart=/opt/cloudfreeze/watchdog.sh",
          "Restart=always",
          "RestartSec=3",
          "",
          "[Install]",
          "WantedBy=multi-user.target",
          "WATCHDOG_UNIT",
          "",
          "# v7: Install inotify-tools for file change rate monitoring",
          "yum install -y inotify-tools 2>/dev/null || apt-get install -y inotify-tools 2>/dev/null || true",
          "",
          "systemctl daemon-reload",
          "systemctl enable --now cloudfreeze-monitor.service",
          "systemctl enable --now cloudfreeze-watchdog.service",
          "echo 'CloudFreeze v7 systemd monitor + watchdog installed and started'",
        ]
      }
    }]
  })

  tags = { Name = "${local.prefix}-realtime-monitor" }
}

# Auto-deploy the agent on all CloudFreeze-monitored instances
resource "aws_ssm_association" "instance_monitor" {
  name = aws_ssm_document.instance_monitor.name

  targets {
    key    = "tag:CloudFreeze"
    values = ["monitored"]
  }

  parameters = {
    LambdaFunctionName = aws_lambda_function.killswitch.function_name
    CpuThreshold       = tostring(var.cpu_threshold)
  }

  # Re-apply when instances change
  schedule_expression = "cron(0 */4 * * ? *)"  # every 4 hours

  compliance_severity = "CRITICAL"
}

# v7 Fix #14: Store canary checksums in SSM Parameter Store (tamper-proof)
resource "aws_ssm_parameter" "canary_checksums" {
  name        = "/cloudfreeze/canary-checksums"
  type        = "SecureString"
  description = "CloudFreeze v7: Tamper-proof canary file checksums"
  value       = "placeholder-will-be-updated-by-user_data"
  tags        = { Name = "${local.prefix}-canary-checksums" }

  lifecycle {
    ignore_changes = [value]  # user_data updates this after canary file creation
  }
}

# v7 Fix #16: Heartbeat alarm — alerts if agent stops sending heartbeats
resource "aws_cloudwatch_metric_alarm" "agent_heartbeat" {
  alarm_name          = "${local.prefix}-agent-heartbeat-missing"
  alarm_description   = "CRITICAL: CloudFreeze monitoring agent has stopped heartbeating"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "Heartbeat"
  namespace           = "CloudFreeze/Agent"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "breaching"  # Missing data = agent is dead
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-agent-heartbeat" }
}


# ══════════════════════════════════════════════════════════════════════════════
#  18. Fix #16: CLOUDWATCH DASHBOARD — Defense System Health Monitor
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_cloudwatch_dashboard" "cloudfreeze" {
  dashboard_name = "${local.prefix}-defense-dashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# 🛡️ CloudFreeze v7 — Autonomous Ransomware Defense Dashboard"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 12
        height = 6
        properties = {
          title   = "Kill-Switch Lambda — Invocations & Errors"
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "${local.prefix}-killswitch", { stat = "Sum", color = "#2ca02c" }],
            ["AWS/Lambda", "Errors",      "FunctionName", "${local.prefix}-killswitch", { stat = "Sum", color = "#d62728" }],
            ["AWS/Lambda", "Throttles",   "FunctionName", "${local.prefix}-killswitch", { stat = "Sum", color = "#ff7f0e" }],
          ]
          period = 60
          region = local.region
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 1
        width  = 12
        height = 6
        properties = {
          title   = "Kill-Switch Lambda — Duration (ms)"
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", "${local.prefix}-killswitch", { stat = "Average", color = "#1f77b4" }],
            ["AWS/Lambda", "Duration", "FunctionName", "${local.prefix}-killswitch", { stat = "p99", color = "#e377c2" }],
          ]
          period = 60
          region = local.region
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 12
        height = 6
        properties = {
          title   = "DLQ — Failed Invocations"
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "${local.prefix}-killswitch-dlq", { stat = "Maximum", color = "#d62728" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "${local.prefix}-restore-dlq",    { stat = "Maximum", color = "#ff7f0e" }],
          ]
          period = 60
          region = local.region
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 7
        width  = 12
        height = 6
        properties = {
          title   = "KMS Encrypt Call Rate (per minute)"
          metrics = [
            ["CloudFreeze/KMS", "KMSEncryptCallCount", { stat = "Sum", color = "#9467bd" }],
          ]
          period = 60
          region = local.region
          view   = "timeSeries"
        }
      },
      {
        type   = "alarm"
        x      = 0
        y      = 13
        width  = 24
        height = 3
        properties = {
          title  = "Alarm Status — All Tripwires"
          alarms = [
            aws_cloudwatch_metric_alarm.kms_rate_alarm.arn,
            aws_cloudwatch_metric_alarm.disk_write_spike.arn,
            aws_cloudwatch_metric_alarm.cpu_spike.arn,
            aws_cloudwatch_metric_alarm.disk_io_spike.arn,
          ]
        }
      },
    ]
  })
}


# ══════════════════════════════════════════════════════════════════════════════
#  19. DLQ ALARM — Alert when failed invocations pile up
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_cloudwatch_metric_alarm" "dlq_alarm" {
  alarm_name          = "${local.prefix}-dlq-has-messages"
  alarm_description   = "CRITICAL: Kill-Switch DLQ has unprocessed failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = aws_sqs_queue.killswitch_dlq.name }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-dlq-alarm" }
}


# ══════════════════════════════════════════════════════════════════════════════
#  21. v7 Fix #20: DYNAMODB THROTTLE ALARMS
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_cloudwatch_metric_alarm" "dynamodb_incidents_throttle" {
  alarm_name          = "${local.prefix}-dynamodb-incidents-throttled"
  alarm_description   = "WARNING: DynamoDB incidents table is being throttled"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions          = { TableName = aws_dynamodb_table.incidents.name }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-dynamodb-incidents-throttle" }
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_kms_rate_throttle" {
  alarm_name          = "${local.prefix}-dynamodb-kms-rate-throttled"
  alarm_description   = "WARNING: DynamoDB KMS rate counter table is being throttled"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions          = { TableName = aws_dynamodb_table.kms_rate.name }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-dynamodb-kms-rate-throttle" }
}


# ══════════════════════════════════════════════════════════════════════════════
#  22. v7: SELF-DEFENSE WATCHDOG LAMBDA
# ══════════════════════════════════════════════════════════════════════════════
# Runs every 5 minutes to verify CloudFreeze infrastructure integrity.
# Detects: EventBridge rule tampering, Lambda code modification, DynamoDB
# table deletion, IAM permission revocation.

resource "aws_iam_role" "lambda_watchdog_role" {
  name = "${local.prefix}-lambda-watchdog-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = { Name = "${local.prefix}-lambda-watchdog-role" }
}

resource "aws_iam_role_policy_attachment" "lambda_watchdog_basic" {
  role       = aws_iam_role.lambda_watchdog_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_watchdog_policy" {
  name = "${local.prefix}-lambda-watchdog-policy"
  role = aws_iam_role.lambda_watchdog_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WatchdogEventBridge"
        Effect = "Allow"
        Action = ["events:ListRules", "events:DescribeRule", "events:EnableRule"]
        Resource = "*"
      },
      {
        Sid    = "WatchdogLambda"
        Effect = "Allow"
        Action = ["lambda:GetFunctionConfiguration"]
        Resource = "*"
      },
      {
        Sid    = "WatchdogDynamoDB"
        Effect = "Allow"
        Action = ["dynamodb:DescribeTable"]
        Resource = [
          aws_dynamodb_table.incidents.arn,
          aws_dynamodb_table.kms_rate.arn,
        ]
      },
      {
        Sid    = "WatchdogEC2"
        Effect = "Allow"
        Action = ["ec2:DescribeSecurityGroups"]
        Resource = "*"
      },
      {
        Sid      = "WatchdogSNS"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.alerts.arn]
      },
      {
        Sid    = "WatchdogSSM"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = "*"
      },
      {
        Sid    = "WatchdogIAM"
        Effect = "Allow"
        Action = ["iam:SimulatePrincipalPolicy", "sts:GetCallerIdentity"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_sqs_queue" "watchdog_dlq" {
  name                      = "${local.prefix}-watchdog-dlq"
  message_retention_seconds = 1209600
  tags                      = { Name = "${local.prefix}-watchdog-dlq" }
}

resource "aws_lambda_function" "watchdog" {
  function_name    = "${local.prefix}-watchdog"
  description      = "CloudFreeze v7 Self-Defense Watchdog: Verifies infrastructure integrity every 5 minutes"
  filename         = "${path.module}/lambda/lambda_watchdog.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/lambda_watchdog.zip")
  handler          = "lambda_watchdog.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 128
  role             = aws_iam_role.lambda_watchdog_role.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.watchdog_dlq.arn
  }

  environment {
    variables = {
      SNS_TOPIC_ARN              = aws_sns_topic.alerts.arn
      DYNAMODB_TABLE             = aws_dynamodb_table.incidents.name
      KMS_RATE_TABLE             = aws_dynamodb_table.kms_rate.name
      QUARANTINE_SG_ID           = aws_security_group.quarantine.id
      KILLSWITCH_FUNCTION_NAME   = aws_lambda_function.killswitch.function_name
      FORENSIC_FUNCTION_NAME     = aws_lambda_function.forensic.function_name
      RESTORE_FUNCTION_NAME      = aws_lambda_function.restore.function_name
      LAMBDA_CODE_HASHES_PARAM   = aws_ssm_parameter.lambda_code_hashes.name
      EXPECTED_EVENTBRIDGE_RULES = jsonencode([
        aws_cloudwatch_event_rule.kms_tripwire.name,
        aws_cloudwatch_event_rule.kms_rate_tripwire.name,
        aws_cloudwatch_event_rule.kms_foreign_key_tripwire.name,
        aws_cloudwatch_event_rule.honeytoken_tripwire.name,
        aws_cloudwatch_event_rule.velocity_tripwire.name,
      ])
    }
  }

  tags = {
    Name        = "${local.prefix}-watchdog"
    CloudFreeze = "self-defense"
  }
}

resource "aws_iam_role_policy" "lambda_watchdog_dlq" {
  name = "${local.prefix}-lambda-watchdog-dlq"
  role = aws_iam_role.lambda_watchdog_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DLQSendMessage"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [aws_sqs_queue.watchdog_dlq.arn]
    }]
  })
}

# v7: SSM Parameter for known-good Lambda code hashes
resource "aws_ssm_parameter" "lambda_code_hashes" {
  name        = "/cloudfreeze/lambda-code-hashes"
  type        = "SecureString"
  description = "CloudFreeze v7: Known-good Lambda function code SHA256 hashes"
  value = jsonencode({
    (aws_lambda_function.killswitch.function_name) = aws_lambda_function.killswitch.source_code_hash
    (aws_lambda_function.forensic.function_name)   = aws_lambda_function.forensic.source_code_hash
    (aws_lambda_function.restore.function_name)    = aws_lambda_function.restore.source_code_hash
  })
  tags = { Name = "${local.prefix}-lambda-code-hashes" }

  lifecycle {
    ignore_changes = [value]  # Updated on each deploy
  }
}

# v7: Scheduled EventBridge rule — runs watchdog every 5 minutes
resource "aws_cloudwatch_event_rule" "watchdog_schedule" {
  name                = "${local.prefix}-watchdog-schedule"
  description         = "CloudFreeze v7: Self-defense watchdog runs every 5 minutes"
  schedule_expression = "rate(5 minutes)"
  tags                = { Name = "${local.prefix}-watchdog-schedule" }
}

resource "aws_cloudwatch_event_target" "watchdog_target" {
  rule      = aws_cloudwatch_event_rule.watchdog_schedule.name
  target_id = "WatchdogLambda"
  arn       = aws_lambda_function.watchdog.arn
}

resource "aws_lambda_permission" "watchdog_schedule" {
  statement_id  = "AllowEventBridgeWatchdog"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.watchdog.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.watchdog_schedule.arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  23. v7: S3 DATA EVENT MONITORING — Bulk Operation Detection
# ══════════════════════════════════════════════════════════════════════════════
# Detects S3-layer ransomware: bulk DeleteObject/PutObject targeting protected buckets.

resource "aws_cloudwatch_event_rule" "s3_bulk_ops_tripwire" {
  name        = "${local.prefix}-s3-bulk-ops-tripwire"
  description = "v7: S3 bulk operation detection — catches S3 data-layer ransomware"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["DeleteObject", "DeleteObjects", "PutObject"]
    }
  })

  tags = { Name = "${local.prefix}-s3-bulk-ops-tripwire" }
}

resource "aws_cloudwatch_event_target" "s3_bulk_to_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_bulk_ops_tripwire.name
  target_id = "S3BulkOpsToLambda"
  arn       = aws_lambda_function.killswitch.arn
}

resource "aws_lambda_permission" "eventbridge_s3_bulk" {
  statement_id  = "AllowEventBridgeS3Bulk"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_bulk_ops_tripwire.arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  24. v7: RDS SUSPICIOUS ACTIVITY MONITORING
# ══════════════════════════════════════════════════════════════════════════════
# Detects RDS-layer attacks: database deletion, snapshot export, modify operations.

resource "aws_cloudwatch_event_rule" "rds_protection_tripwire" {
  name        = "${local.prefix}-rds-protection-tripwire"
  description = "v7: RDS suspicious activity detection — catches database-layer ransomware"

  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["rds.amazonaws.com"]
      eventName   = [
        "DeleteDBInstance",
        "DeleteDBCluster",
        "ModifyDBInstance",
        "CreateDBSnapshot",
        "RestoreDBInstanceFromDBSnapshot",
      ]
    }
  })

  tags = { Name = "${local.prefix}-rds-protection-tripwire" }
}

resource "aws_cloudwatch_event_target" "rds_to_lambda" {
  rule      = aws_cloudwatch_event_rule.rds_protection_tripwire.name
  target_id = "RDSProtectionToLambda"
  arn       = aws_lambda_function.killswitch.arn
}

resource "aws_lambda_permission" "eventbridge_rds" {
  statement_id  = "AllowEventBridgeRDS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rds_protection_tripwire.arn
}


# ══════════════════════════════════════════════════════════════════════════════
#  25. v7: SELF-DEFENSE ALARMS — Detect Tampering of CloudFreeze Itself
# ══════════════════════════════════════════════════════════════════════════════

# Alert if any EventBridge rule is disabled (attacker tampering)
resource "aws_cloudwatch_event_rule" "self_defense_eventbridge" {
  name        = "${local.prefix}-self-defense-eventbridge"
  description = "v7 Self-Defense: Alert if any EventBridge rule is disabled"

  event_pattern = jsonencode({
    source      = ["aws.events"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["events.amazonaws.com"]
      eventName   = ["DisableRule", "DeleteRule"]
    }
  })

  tags = { Name = "${local.prefix}-self-defense-eventbridge" }
}

resource "aws_cloudwatch_event_target" "self_defense_eventbridge" {
  rule      = aws_cloudwatch_event_rule.self_defense_eventbridge.name
  target_id = "SelfDefenseEventBridgeToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# v7: Kill-switch Lambda error rate alarm
resource "aws_cloudwatch_metric_alarm" "killswitch_error_rate" {
  alarm_name          = "${local.prefix}-killswitch-error-rate"
  alarm_description   = "CRITICAL: Kill-Switch Lambda is experiencing errors — defense may be degraded"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.killswitch.function_name }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = { Name = "${local.prefix}-killswitch-error-alarm" }
}

# v7: ECS permissions for enhanced takedown
resource "aws_iam_role_policy" "lambda_ecs_enhanced" {
  name = "${local.prefix}-lambda-ecs-enhanced"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ECSEnhancedTakedown"
      Effect = "Allow"
      Action = [
        "ecs:StopTask",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskDefinition",
      ]
      Resource = "*"
    }]
  })
}
