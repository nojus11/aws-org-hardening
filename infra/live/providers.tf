terraform {
  required_version = ">= 1.10" # native S3 state locking

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69" # 6.69+ needed: GuardDuty RDS_DATA_RISK (security)
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "live"

  default_tags {
    tags = {
      ManagedBy = "terraform"
    }
  }
}
