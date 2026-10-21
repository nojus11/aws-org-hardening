# Customer-managed key for the audit-evidence buckets: the org CloudTrail
# trail (log + digest files) and AWS Config (deliveries from all 4
# accounts). Reading a log then needs S3 access AND kms:Decrypt on this key.
# Disabling/deleting it would stop log delivery: protected by the
# ProtectLogArchive SCP (infra/management/scp.tf).
resource "aws_kms_key" "log_archive" {
  description             = "Audit-evidence logs: org CloudTrail + AWS Config"
  enable_key_rotation     = true # new key material yearly, automatically
  deletion_window_in_days = 30   # max grace period before a deletion is final

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Standard: IAM policies in this (security) account decide who may
        # manage and decrypt. Today that's the admin role (AdministratorAccess).
        Sid       = "SecurityAccountIAM"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # CloudTrail may encrypt only for our org trail, and only files
        # labelled as coming from a trail in the management account.
        Sid       = "CloudTrailEncryptOrgTrailOnly"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.org_trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.management_account_id}:trail/*" }
        }
      },
      {
        # Needed because the bucket will use an S3 Bucket Key.
        Sid       = "CloudTrailDescribeKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.org_trail_arn } }
      },
      {
        # Config writes as the Config service (we use its service-linked
        # role), only on behalf of our 4 accounts.
        Sid       = "ConfigDeliveryFromOurAccounts"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = local.config_source_accounts } }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "log_archive" {
  name          = "alias/log-archive"
  target_key_id = aws_kms_key.log_archive.key_id
}
