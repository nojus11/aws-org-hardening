# Settings every account should have (us-east-1 — the provider's region).

# New EBS volumes are always encrypted (AWS-managed key).
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# Disk snapshots can never be shared publicly.
resource "aws_ebs_snapshot_block_public_access" "this" {
  state = "block-all-sharing"
}

# New instances require IMDSv2 (session tokens), which blocks SSRF-style
# theft of instance credentials. A lab can still opt one instance into v1.
resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens = "required"
}

# Default VPCs deleted in us-east-1 on 2026-10-17 (FSBP EC2.15: their subnets
# give every instance a public IP). Every network is built deliberately;
# `aws ec2 create-default-vpc` recreates one if ever needed.

# No VPC can reach or be reached from the internet (VPC Block Public
# Access), unless a VPC/subnet gets an explicit exclusion. Off for lab.
resource "aws_vpc_block_public_access_options" "this" {
  count = var.block_vpc_internet ? 1 : 0

  internet_gateway_block_mode = "block-bidirectional"
}

# Backstop for any future IAM user (SSO is the norm here).
resource "aws_iam_account_password_policy" "this" {
  #checkov:skip=CKV_AWS_9:no forced expiry, per NIST SP 800-63B
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
  # No forced expiry: NIST SP 800-63B advises against periodic rotation.
}

# Account-wide S3 Block Public Access (off for lab, which attacks public buckets).
resource "aws_s3_account_public_access_block" "this" {
  count = var.block_public_s3 ? 1 : 0

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# SSM documents (scripts Systems Manager can run on instances) can't be
# shared publicly. Account-level, per region; FSBP SSM.7 (critical).
resource "aws_ssm_service_setting" "block_public_document_sharing" {
  setting_id    = "/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

# Flags access from outside THIS account — incl. my own other accounts
# (the live → management trust bug class). Free.
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "account-external-access"
  type          = "ACCOUNT"
}

# Expected: SSO roles trusted by this account's own Identity Center SAML
# provider (that's how I log in). Auto-archive them so only unexpected
# findings stay active — including for future permission sets.
resource "aws_accessanalyzer_archive_rule" "sso_roles" {
  analyzer_name = aws_accessanalyzer_analyzer.account.analyzer_name
  rule_name     = "expected-sso-roles"

  filter {
    criteria = "resource"
    contains = ["role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_"]
  }
  filter {
    criteria = "principal.Federated"
    contains = ["saml-provider/AWSSSO_"]
  }
}

# --- AWS Config: record every resource's configuration and its changes ---

# Config's own role: AWS-managed permissions, usable only by the Config service.
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true # IAM etc. — us-east-1 is our only region
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "default"
  s3_bucket_name = var.config_bucket_name
  s3_kms_key_arn = var.config_kms_key_arn # the log-archive key in security

  depends_on = [aws_config_configuration_recorder.this]
}

# A recorder starts switched off; turn it on once delivery is set up.
resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# --- Alerting spoke: forward security-relevant events to the hub in security ---

data "aws_caller_identity" "current" {}

# EventBridge needs a role to deliver to a bus in another account or region.
# Only this account's forward-* rules can use it, and only to reach the hub.
resource "aws_iam_role" "alert_forwarder" {
  name = "alert-forwarder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        ArnLike      = { "aws:SourceArn" = "arn:aws:events:*:${data.aws_caller_identity.current.account_id}:rule/forward-*" }
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "alert_forwarder" {
  name = "put-events-to-hub"
  role = aws_iam_role.alert_forwarder.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = var.alert_hub_bus_arn
    }]
  })
}

# Main forwarder (us-east-1): changes to the services the hub watches, plus
# new Access Analyzer findings. Root is excluded: the root forwarder sends it.
resource "aws_cloudwatch_event_rule" "forward_security_events" {
  name        = "forward-security-events"
  description = "Forward security-relevant changes to the alerting hub in security"
  event_pattern = jsonencode({
    "$or" = [
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = [
            "cloudtrail.amazonaws.com", "config.amazonaws.com", "guardduty.amazonaws.com",
            "securityhub.amazonaws.com", "access-analyzer.amazonaws.com", "events.amazonaws.com",
            "sns.amazonaws.com", "organizations.amazonaws.com", "iam.amazonaws.com",
            "sso.amazonaws.com", "sso-directory.amazonaws.com", "identitystore.amazonaws.com",
          ]
          userIdentity = { type = [{ "anything-but" = ["Root"] }] }
        }
      },
      { source = ["aws.access-analyzer"], "detail-type" = ["Access Analyzer Finding"] },
    ]
  })
}

resource "aws_cloudwatch_event_target" "forward_security_events" {
  rule     = aws_cloudwatch_event_rule.forward_security_events.name
  arn      = var.alert_hub_bus_arn
  role_arn = aws_iam_role.alert_forwarder.arn
}

# Root forwarder: root sign-ins, anything done as root, AssumeRoot. These are
# recorded in the region of the endpoint used, so management watches every
# region. Includes read-only events: set before we verified AssumeRoot is a
# write event; harmless, so left as is.
resource "aws_cloudwatch_event_rule" "forward_root_events" {
  for_each = var.root_forwarder_regions

  region      = each.key
  name        = "forward-root-events"
  description = "Forward root sign-ins, root activity and AssumeRoot to the alerting hub"
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
  event_pattern = jsonencode({
    "$or" = [
      {
        "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail", "AWS Console Signin via CloudTrail"]
        detail        = { userIdentity = { type = ["Root"] } }
      },
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail        = { eventSource = ["sts.amazonaws.com"], eventName = ["AssumeRoot"] }
      },
    ]
  })
}

resource "aws_cloudwatch_event_target" "forward_root_events" {
  for_each = var.root_forwarder_regions

  region   = each.key
  rule     = aws_cloudwatch_event_rule.forward_root_events[each.key].name
  arn      = var.alert_hub_bus_arn
  role_arn = aws_iam_role.alert_forwarder.arn
}
