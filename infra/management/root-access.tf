# Centralized root access: member accounts have no root password, keys or MFA.
# Root-only tasks run as short-lived privileged sessions from management.
resource "aws_iam_organizations_features" "root_access" {
  enabled_features = [
    "RootCredentialsManagement",
    "RootSessions",
  ]

  # Org-wide IAM access must be on before the features can be enabled
  depends_on = [aws_organizations_organization.this]

  lifecycle {
    prevent_destroy = true
  }
}
