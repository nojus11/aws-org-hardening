variable "security_account_id" {
  description = "Security account: log archive, alerting hub, Config bucket."
  type        = string
}

variable "log_archive_kms_key_id" {
  description = "KMS key (in security) that encrypts CloudTrail and Config logs."
  type        = string
}
