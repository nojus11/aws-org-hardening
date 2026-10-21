# Alerting hub: every account forwards its security-relevant events to one
# bus here; alert rules (alerting-rules.tf) match them and email via SNS.
# us-east-1 (provider default). local.org_id is defined in cloudtrail-logs.tf.
locals {
  alert_email = var.alert_email
}

# Events in: the central bus. Only accounts in my organization may send.
resource "aws_cloudwatch_event_bus" "org_events" {
  name = "org-security-events"
}

resource "aws_cloudwatch_event_bus_policy" "org_events" {
  event_bus_name = aws_cloudwatch_event_bus.org_events.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgAccountsCanSend"
      Effect    = "Allow"
      Principal = "*"
      Action    = "events:PutEvents"
      Resource  = aws_cloudwatch_event_bus.org_events.arn
      Condition = { StringEquals = { "aws:PrincipalOrgID" = local.org_id } }
    }]
  })
}

# Alerts out: SNS topic → email. Only rules on the bus above may publish.
resource "aws_sns_topic" "alerts" {
  #checkov:skip=CKV_AWS_26:accepted: alert one-liners are low-sensitivity; a CMK for EventBridge -> SNS is a possible later step
  name = "security-alerts"
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AlertRulesCanPublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        ArnLike = {
          "aws:SourceArn" = "arn:aws:events:us-east-1:${data.aws_caller_identity.current.account_id}:rule/${aws_cloudwatch_event_bus.org_events.name}/*"
        }
      }
    }]
  })
}

# AWS emails a confirmation link. Don't click it: confirm via the CLI with
# --authenticate-on-unsubscribe true, so the unsubscribe link in every alert
# email needs an AWS login (done 2026-10-18; redo whenever this is recreated).
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = local.alert_email
}
