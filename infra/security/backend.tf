terraform {
  backend "s3" {
    # bucket: from backend.hcl (terraform init -backend-config=backend.hcl)
    key          = "security/terraform.tfstate"
    region       = "us-east-1"
    profile      = "security"
    use_lockfile = true
  }
}
