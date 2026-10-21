terraform {
  backend "s3" {
    # bucket: from backend.hcl (terraform init -backend-config=backend.hcl)
    key          = "live/terraform.tfstate"
    region       = "us-east-1"
    profile      = "live"
    use_lockfile = true
  }
}
