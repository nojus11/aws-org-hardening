module "state" {
  source = "../modules/state-bucket"
}

module "baseline" {
  source             = "../modules/account-baseline"
  config_bucket_name = aws_s3_bucket.config_logs.id
  config_kms_key_arn = aws_kms_key.log_archive.arn
  alert_hub_bus_arn  = aws_cloudwatch_event_bus.org_events.arn
}
