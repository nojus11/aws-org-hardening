# Org-wide trail: every account, every region. Logs go to the locked bucket
# in the security account (infra/security/cloudtrail-logs.tf).
resource "aws_cloudtrail" "org" {
  #checkov:skip=CKV2_AWS_10:alerting via EventBridge, not CloudWatch Logs
  #checkov:skip=CKV_AWS_252:no SNS on the trail; alerts go EventBridge -> SNS
  name                          = "org-trail"
  s3_bucket_name                = "cloudtrail-logs-${local.security_account_id}"
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true # IAM, STS, Organizations etc.
  enable_log_file_validation    = true # hourly signed digests detect tampering

  # Encrypt log + digest files with our key in security (log-archive-key.tf).
  # ARN built from the key ID in terraform.tfvars, like the trail ARN on the
  # other side: no reading security's state from here.
  kms_key_id = "arn:aws:kms:us-east-1:${local.security_account_id}:key/${var.log_archive_kms_key_id}"

  # Advanced selectors REPLACE the default: management events must be
  # listed explicitly or the trail (and every alert) stops seeing them.
  advanced_event_selector {
    name = "All management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # Terraform state: every read and write (it maps the whole infrastructure).
  advanced_event_selector {
    name = "Terraform state buckets: all object access"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field = "resources.ARN"
      starts_with = [
        "arn:aws:s3:::tfstate-${aws_organizations_account.management.id}/",
        "arn:aws:s3:::tfstate-${aws_organizations_account.live.id}/",
        "arn:aws:s3:::tfstate-${aws_organizations_account.lab.id}/",
        "arn:aws:s3:::tfstate-${local.security_account_id}/",
      ]
    }
  }

  # Log archive: reads only. Logging writes would log CloudTrail's own
  # deliveries into this bucket (a loop); writes are locked anyway.
  advanced_event_selector {
    name = "Log archive: reads only"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field  = "readOnly"
      equals = ["true"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["arn:aws:s3:::cloudtrail-logs-${local.security_account_id}/"]
    }
  }

  # Org-wide CloudTrail access must be on before an org trail can exist
  depends_on = [aws_organizations_organization.this]

  lifecycle {
    prevent_destroy = true
  }
}
