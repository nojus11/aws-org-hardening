# The drift-check role comes from the baseline module (every account).
# SecurityAudit lacks these reads, and the resources exist only here.
# Proven by the first run (2026-10-21): ViewBudget, GetAnomalyMonitors,
# DescribeUser, DescribeGroup. Predicted (skipped in that run, or tag reads):
# the rest. Remove any that turn out unused.
resource "aws_iam_role_policy" "github_drift_check_management" {
  name = "read-management-only"
  role = module.baseline.github_drift_check_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Budget"
        Effect   = "Allow"
        Action   = ["budgets:ViewBudget", "budgets:ListTagsForResource"]
        Resource = "arn:aws:budgets::${aws_organizations_account.management.id}:budget/*"
      },
      {
        Sid    = "CostAnomaly"
        Effect = "Allow"
        Action = ["ce:GetAnomalyMonitors", "ce:GetAnomalySubscriptions", "ce:ListTagsForResource"]
        Resource = [
          "arn:aws:ce::${aws_organizations_account.management.id}:anomalymonitor/*",
          "arn:aws:ce::${aws_organizations_account.management.id}:anomalysubscription/*",
        ]
      },
      {
        Sid    = "IdentityCenter"
        Effect = "Allow"
        Action = ["identitystore:DescribeUser", "identitystore:DescribeGroup", "identitystore:DescribeGroupMembership"]
        Resource = [
          "arn:aws:identitystore::${aws_organizations_account.management.id}:identitystore/${local.identity_store_id}",
          "arn:aws:identitystore:::user/*",
          "arn:aws:identitystore:::group/*",
          "arn:aws:identitystore:::membership/*",
        ]
      },
    ]
  })
}
