# Central bucket for AWS Config recordings from all 4 accounts. Separate from
# the CloudTrail archive: "what things looked like" vs "who did what".
locals {
  config_source_accounts = [
    var.member_accounts.management.account_id,
    var.member_accounts.live.account_id,
    var.member_accounts.lab.account_id,
    data.aws_caller_identity.current.account_id, # security
  ]
}

resource "aws_s3_bucket" "config_logs" {
  #checkov:skip=CKV_AWS_18:accepted: low-sensitivity snapshots; KMS + bucket policy restrict access
  #checkov:skip=CKV_AWS_144:single-region by design (RestrictRegions SCP)
  #checkov:skip=CKV2_AWS_62:no event notifications needed
  bucket = "config-logs-${data.aws_caller_identity.current.account_id}"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_archive.arn
    }
    bucket_key_enabled = true # S3 reuses a bucket-level data key: far fewer KMS calls
  }
}

resource "aws_s3_bucket_public_access_block" "config_logs" {
  bucket                  = aws_s3_bucket.config_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "config_logs" {
  #checkov:skip=CKV_AWS_300:only AWS services write small single-part files; no multipart uploads
  bucket = aws_s3_bucket.config_logs.id
  rule {
    id     = "expire-after-1-year"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }
}

# Only the Config service, and only on behalf of my 4 accounts, may write.
resource "aws_s3_bucket_policy" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ConfigBucketChecks"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.config_logs.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.config_source_accounts } }
      },
      {
        Sid       = "ConfigDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = [for id in local.config_source_accounts : "${aws_s3_bucket.config_logs.arn}/AWSLogs/${id}/Config/*"]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = local.config_source_accounts
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.config_logs.arn, "${aws_s3_bucket.config_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}
