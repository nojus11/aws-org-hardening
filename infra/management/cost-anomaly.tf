# AWS auto-created these (Default-Services-*); imported 2026-10-14.
resource "aws_ce_anomaly_monitor" "services" {
  name              = "Default-Services-Monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

resource "aws_ce_anomaly_subscription" "daily" {
  name             = "Default-Services-Subscription"
  frequency        = "DAILY"
  monitor_arn_list = [aws_ce_anomaly_monitor.services.arn]

  subscriber {
    type    = "EMAIL"
    address = var.account_emails.management
  }

  # Alert when an anomaly's unexpected extra cost reaches half the monthly
  # budget. AWS's default ($100 AND 40%) would never fire at my spend.
  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = [tostring(local.monthly_budget_usd / 2)]
    }
  }
}
