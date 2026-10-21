variable "block_public_s3" {
  description = "Turn on account-level S3 Block Public Access (false for lab)."
  type        = bool
  default     = true
}

variable "block_vpc_internet" {
  description = "Turn on account-level VPC Block Public Access (false for lab)."
  type        = bool
  default     = true
}

variable "config_bucket_name" {
  description = "Central S3 bucket (in security) that receives AWS Config recordings."
  type        = string
}

variable "config_kms_key_arn" {
  description = "KMS key (in security) that encrypts this account's Config deliveries."
  type        = string
}

variable "alert_hub_bus_arn" {
  description = "Central alerting event bus (in security) that this account forwards events to."
  type        = string
}

variable "root_forwarder_regions" {
  description = "Regions that forward root sign-ins, root activity and AssumeRoot (all regions for management)."
  type        = set(string)
  default     = ["us-east-1"]
}
