output "alert_forwarder_role_arn" {
  description = "Role that this account's forward-* rules use to send events to the alerting hub."
  value       = aws_iam_role.alert_forwarder.arn
}
