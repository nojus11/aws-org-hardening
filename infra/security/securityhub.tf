# Security Hub CSPM, configured centrally from here (home region us-east-1).
# Designating this account as admin (infra/management/securityhub.tf) also
# switched Security Hub on here, with AWS's default standards; the policy
# below replaces those.

# Central configuration requires an aggregator. NO_REGIONS = us-east-1 only.
resource "aws_securityhub_finding_aggregator" "this" {
  linking_mode = "NO_REGIONS"
}

# Switch the org from per-account settings to one central policy.
resource "aws_securityhub_organization_configuration" "this" {
  auto_enable           = false
  auto_enable_standards = "NONE"
  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [aws_securityhub_finding_aggregator.this]
}

# On, FSBP only, every FSBP control including ones AWS adds later.
resource "aws_securityhub_configuration_policy" "fsbp" {
  name        = "fsbp-only"
  description = "Security Hub on, FSBP standard only, all its controls"
  configuration_policy {
    service_enabled       = true
    enabled_standard_arns = ["arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"]
    security_controls_configuration {
      disabled_control_identifiers = []
    }
  }

  depends_on = [aws_securityhub_organization_configuration.this]
}

# Attach to the org root: all 4 accounts, plus any future ones.
# Root ID from terraform.tfvars, like the trail ARN: reading it from
# management would weaken the boundary.
resource "aws_securityhub_configuration_policy_association" "root" {
  target_id = var.org_root_id
  policy_id = aws_securityhub_configuration_policy.fsbp.id
}
