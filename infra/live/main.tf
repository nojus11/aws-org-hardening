module "state" {
  source = "../modules/state-bucket"
}

module "baseline" {
  source             = "../modules/account-baseline"
  config_bucket_name = "config-logs-${var.security_account_id}"
  config_kms_key_arn = "arn:aws:kms:us-east-1:${var.security_account_id}:key/${var.log_archive_kms_key_id}"
  alert_hub_bus_arn  = "arn:aws:events:us-east-1:${var.security_account_id}:event-bus/org-security-events"
}
