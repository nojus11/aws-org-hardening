# Log archive for the org CloudTrail trail (trail lives in infra/management).
# Locked in governance mode for 1 year, then expired.

data "aws_caller_identity" "current" {}

locals {
  org_id                = var.org_id
  management_account_id = var.member_accounts.management.account_id
  # We choose the trail's name in infra/management, so its ARN is known in
  # advance; built here, so this root never reads management's state.
  org_trail_arn = "arn:aws:cloudtrail:us-east-1:${local.management_account_id}:trail/org-trail"
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  #checkov:skip=CKV_AWS_18:reads logged via CloudTrail data events
  #checkov:skip=CKV_AWS_144:single-region by design (RestrictRegions SCP); Object Lock + digests protect integrity
  #checkov:skip=CKV2_AWS_62:no event notifications needed
  bucket              = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_archive.arn
    }
    bucket_key_enabled = true # S3 reuses a bucket-level data key: far fewer KMS calls
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  #checkov:skip=CKV_AWS_300:only AWS services write small single-part files; no multipart uploads
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    id     = "expire-after-1-year"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    # With versioning, expiry only hides the file; this removes it for real
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.org_trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource = [
          "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.management_account_id}/*",
          "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.org_id}/*",
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.org_trail_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}
