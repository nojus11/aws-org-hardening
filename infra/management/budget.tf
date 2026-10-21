# Single source of truth for spend limits — the cost anomaly threshold
# (cost-anomaly.tf) is derived from it.
locals {
  monthly_budget_usd = 10
}

resource "aws_budgets_budget" "monthly" {
  name         = "monthly-total"
  budget_type  = "COST"
  limit_amount = tostring(local.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Early warning: half the budget already spent
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.account_emails.management]
  }

  # Over budget: the whole budget spent
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.account_emails.management]
  }

  # Heading over: AWS forecasts more than the budget this month
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.account_emails.management]
  }
}
