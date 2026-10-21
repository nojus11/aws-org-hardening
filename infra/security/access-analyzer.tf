# Flags anything reachable from OUTSIDE the org (public buckets, roles
# trusting foreign accounts, …). Free. us-east-1 only: all resources live
# here; other regions are covered by the region SCP, GuardDuty and Prowler.
resource "aws_accessanalyzer_analyzer" "org" {
  analyzer_name = "org-external-access"
  type          = "ORGANIZATION"
}

# Same expected SSO-role findings, seen org-wide: auto-archive them.
resource "aws_accessanalyzer_archive_rule" "org_sso_roles" {
  analyzer_name = aws_accessanalyzer_analyzer.org.analyzer_name
  rule_name     = "expected-sso-roles"

  filter {
    criteria = "resource"
    contains = ["role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_"]
  }
  filter {
    criteria = "principal.Federated"
    contains = ["saml-provider/AWSSSO_"]
  }
}
