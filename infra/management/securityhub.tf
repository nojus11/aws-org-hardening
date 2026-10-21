# Security runs Security Hub CSPM for the org. us-east-1 only (provider
# default); central configuration, set up from security, takes it from here.
resource "aws_securityhub_organization_admin_account" "security" {
  admin_account_id = aws_organizations_account.security.id

  depends_on = [aws_organizations_organization.this]
}

# Central configuration can't switch Security Hub on in the management
# account, and management can't switch itself on while centrally managed.
# Rebuild order: apply this BEFORE security's root association. If the
# association comes first (as on 2026-10-16): make management
# SELF_MANAGED_SECURITY_HUB temporarily, apply this, then remove that.
# No default standards: security's policy (FSBP only) decides what runs here.
resource "aws_securityhub_account" "management" {
  enable_default_standards = false
}
