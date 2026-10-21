# Account IDs come from the accounts this root manages (organization.tf).
locals {
  security_account_id = aws_organizations_account.security.id
}

module "state" {
  source = "../modules/state-bucket"
}

module "baseline" {
  source                 = "../modules/account-baseline"
  config_bucket_name     = "config-logs-${local.security_account_id}"
  config_kms_key_arn     = "arn:aws:kms:us-east-1:${local.security_account_id}:key/${var.log_archive_kms_key_id}"
  alert_hub_bus_arn      = "arn:aws:events:us-east-1:${local.security_account_id}:event-bus/org-security-events"
  root_forwarder_regions = data.aws_regions.enabled.names
}
