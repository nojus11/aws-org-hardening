variable "region" {
  description = "Region this GuardDuty setup lives in."
  type        = string
}

variable "protection_plans" {
  description = "GuardDuty paid protection plans: name => { status = ENABLED/DISABLED }."
  type = map(object({
    status = string
  }))
}

variable "members" {
  description = "Existing org accounts to add as GuardDuty members: name => { account_id, email }."
  type = map(object({
    account_id = string
    email      = string
  }))
  default = {}
}

variable "plans_enforced_on" {
  description = "Member account whose plans the admin sets explicitly (one that had GuardDuty before joining, i.e. management). null = none."
  type        = string
  default     = null
}

variable "alert_hub_bus_arn" {
  description = "Central alerting event bus that GuardDuty findings are forwarded to."
  type        = string
}

variable "alert_forwarder_role_arn" {
  description = "Role EventBridge uses to deliver to the hub (from account-baseline)."
  type        = string
}
