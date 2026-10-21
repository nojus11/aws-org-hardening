variable "account_emails" {
  description = "Root email per account (management, live, lab, security); billing alerts go to management's."
  type        = map(string)
}

variable "sso_user_email" {
  description = "Email of my Identity Center user."
  type        = string
}

variable "log_archive_kms_key_id" {
  description = "KMS key (in security) that encrypts CloudTrail and Config logs."
  type        = string
}
