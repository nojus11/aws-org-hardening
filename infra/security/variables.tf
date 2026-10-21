variable "member_accounts" {
  description = "The org's other accounts (security is this one): ID + root email."
  type = map(object({
    account_id = string
    email      = string
  }))
}

variable "org_id" {
  description = "Organization ID (o-…): only accounts in it may send alerts or logs."
  type        = string
}

variable "org_root_id" {
  description = "Organization root (r-…): Security Hub policy attaches here."
  type        = string
}

variable "alert_email" {
  description = "Where security alerts are emailed (SNS)."
  type        = string
}
