resource "aws_organizations_organization" "this" {
  aws_service_access_principals = ["access-analyzer.amazonaws.com", "cloudtrail.amazonaws.com", "guardduty.amazonaws.com", "iam.amazonaws.com", "securityhub.amazonaws.com", "sso.amazonaws.com"]
  enabled_policy_types          = ["AISERVICES_OPT_OUT_POLICY", "DECLARATIVE_POLICY_EC2", "RESOURCE_CONTROL_POLICY", "SERVICE_CONTROL_POLICY"]
  feature_set                   = "ALL"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_organizational_unit" "live" {
  name      = "Live"
  parent_id = aws_organizations_organization.this.roots[0].id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_organizational_unit" "lab" {
  name      = "Lab"
  parent_id = aws_organizations_organization.this.roots[0].id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "management" {
  name              = "Management Account"
  email             = var.account_emails.management
  parent_id         = aws_organizations_organization.this.roots[0].id
  close_on_deletion = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "live" {
  name              = "Live Account"
  email             = var.account_emails.live
  parent_id         = aws_organizations_organizational_unit.live.id
  close_on_deletion = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "lab" {
  name              = "Lab Account"
  email             = var.account_emails.lab
  parent_id         = aws_organizations_organizational_unit.lab.id
  close_on_deletion = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.this.roots[0].id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "security" {
  name              = "Security Account"
  email             = var.account_emails.security
  parent_id         = aws_organizations_organizational_unit.security.id
  close_on_deletion = false

  lifecycle {
    prevent_destroy = true
  }
}
