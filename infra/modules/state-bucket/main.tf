# Hardened S3 bucket for Terraform remote state.
# Account-neutral: it builds in whichever account the caller's provider uses.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_145:SSE-S3 accepted: private, versioned, HTTPS-only, reads logged
  #checkov:skip=CKV_AWS_18:access logged via CloudTrail data events instead
  #checkov:skip=CKV_AWS_144:single-region by design (RestrictRegions SCP)
  #checkov:skip=CKV2_AWS_61:no lifecycle: old state versions kept on purpose for recovery
  #checkov:skip=CKV2_AWS_62:no event notifications needed
  bucket = "tfstate-${data.aws_caller_identity.current.account_id}"

  lifecycle {
    prevent_destroy = true
  }
}

# Keep every old version of the state so a bad write can be rolled back.
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lock every new state version for a year. Compliance mode: no one, not even
# root, can delete it early, so a bad or malicious write can be rolled back.
resource "aws_s3_bucket_object_lock_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Secure on its own — never rely on account-level Block Public Access.
resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.state.arn,
        "${aws_s3_bucket.state.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
