output "alert_forwarder_role_arn" {
  description = "Role that this account's forward-* rules use to send events to the alerting hub."
  value       = aws_iam_role.alert_forwarder.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions OIDC provider in this account, for roles GitHub may assume."
  value       = aws_iam_openid_connect_provider.github.arn
}

output "github_drift_check_role_name" {
  description = "Read-only role GitHub's daily drift check uses."
  value       = aws_iam_role.github_drift_check.name
}
