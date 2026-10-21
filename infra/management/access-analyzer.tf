# Security runs the org-wide Access Analyzer.
resource "aws_organizations_delegated_administrator" "access_analyzer" {
  account_id        = aws_organizations_account.security.id
  service_principal = "access-analyzer.amazonaws.com"

  depends_on = [aws_organizations_organization.this]
}
