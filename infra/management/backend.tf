terraform {
  backend "s3" {
    # bucket: from backend.hcl (terraform init -backend-config=backend.hcl)
    key          = "management/terraform.tfstate"
    region       = "us-east-1"
    profile      = "management"
    use_lockfile = true
  }
}
