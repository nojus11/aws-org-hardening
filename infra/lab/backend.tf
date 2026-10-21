terraform {
  backend "s3" {
    # bucket: from backend.hcl (terraform init -backend-config=backend.hcl)
    key          = "lab/terraform.tfstate"
    region       = "us-east-1"
    profile      = "lab"
    use_lockfile = true
  }
}
