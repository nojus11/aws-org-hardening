# Alert rules on the hub bus (alerting.tf): each matches forwarded events and
# emails a one-line summary via SNS. Patterns max 2,048 characters each.

locals {
  # One-line message formats, by event shape. EventBridge fills each <name>
  # from the event path given in `paths` (input transformer).
  alert_formats = {
    api_call = {
      paths = {
        account = "$.account", region = "$.region", time = "$.time",
        service = "$.detail.eventSource", action = "$.detail.eventName",
        who     = "$.detail.userIdentity.arn", ip = "$.detail.sourceIPAddress",
        error   = "$.detail.errorCode"
      }
      text = "<action> (<service>) in account <account>, <region> | error: <error> | by <who> from <ip> | <time>"
    }
    signin = {
      paths = {
        account = "$.account", region = "$.region", time = "$.time",
        who     = "$.detail.userIdentity.arn", ip = "$.detail.sourceIPAddress",
        result  = "$.detail.responseElements.ConsoleLogin", mfa = "$.detail.additionalEventData.MFAUsed"
      }
      text = "<result> (MFA: <mfa>) in account <account>, <region> | <who> from <ip> | <time>"
    }
    access_analyzer = {
      paths = {
        account = "$.detail.accountId", region = "$.detail.region",
        type    = "$.detail.resourceType", resource = "$.detail.resource", public = "$.detail.isPublic"
      }
      text = "<type> <resource> in account <account>, <region> | public: <public>"
    }
    guardduty = {
      paths = {
        account  = "$.detail.accountId", region = "$.detail.region",
        severity = "$.detail.severity", type = "$.detail.type", title = "$.detail.title"
      }
      text = "severity <severity>: <title> (<type>) in account <account>, <region>"
    }
  }

  api_call = ["AWS API Call via CloudTrail"]

  # Lambda event names carry an API version suffix
  # (UpdateFunctionCode20150331v2): match by prefix.
  responder_lambda_actions = [
    { prefix = "UpdateFunctionCode" }, { prefix = "UpdateFunctionConfiguration" },
    { prefix = "DeleteFunction" }, { prefix = "PutFunctionConcurrency" },
    { prefix = "AddPermission" }, { prefix = "RemovePermission" },
  ]

  alert_rules = {
    root-signin = {
      title  = "Root console sign-in"
      format = "signin"
      # AWS docs and real events spell this detail-type differently; match both.
      pattern = jsonencode({
        "detail-type" = ["AWS Console Sign In via CloudTrail", "AWS Console Signin via CloudTrail"]
        detail        = { userIdentity = { type = ["Root"] } }
      })
    }
    root-activity = {
      title  = "Change made as root"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        detail        = { userIdentity = { type = ["Root"] } }
      })
    }
    assume-root = {
      title  = "AssumeRoot (short-term root session)"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        detail        = { eventSource = ["sts.amazonaws.com"], eventName = ["AssumeRoot"] }
      })
    }
    logging-tampering = {
      title  = "Logging changed or stopped"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        detail = {
          eventSource = ["cloudtrail.amazonaws.com", "config.amazonaws.com"]
          eventName = [
            "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
            "DeleteEventDataStore", "StopEventDataStoreIngestion",
            "StopConfigurationRecorder", "DeleteConfigurationRecorder", "PutConfigurationRecorder",
            "DeleteDeliveryChannel", "PutDeliveryChannel", "DeleteRetentionConfiguration",
          ]
        }
      })
    }
    detection-tampering = {
      title  = "Threat detection changed, disabled or suppressed"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        detail = {
          eventSource = ["guardduty.amazonaws.com", "securityhub.amazonaws.com", "access-analyzer.amazonaws.com"]
          eventName = [
            # GuardDuty: off, detached, or findings suppressed (filters, trusted IPs)
            "DeleteDetector", "UpdateDetector", "UpdateMemberDetectors", "CreateFilter", "UpdateFilter",
            "CreateIPSet", "UpdateIPSet", "DeletePublishingDestination",
            # Security Hub: off, standards/controls off, policy changed, auto-suppression rules
            "DisableSecurityHub", "BatchDisableStandards", "UpdateStandardsControl",
            "BatchUpdateStandardsControlAssociations", "UpdateConfigurationPolicy", "DeleteConfigurationPolicy",
            "StartConfigurationPolicyAssociation", "StartConfigurationPolicyDisassociation",
            "DeleteFindingAggregator", "CreateAutomationRule", "BatchUpdateAutomationRules",
            # Access Analyzer: analyzer deleted, findings archived
            "DeleteAnalyzer", "CreateArchiveRule", "UpdateArchiveRule", "ApplyArchiveRule", "UpdateFindings",
            # Org-level detachment (GuardDuty and Security Hub share these names)
            "DisableOrganizationAdminAccount", "UpdateOrganizationConfiguration",
            "DisassociateFromAdministratorAccount", "DisassociateFromMasterAccount",
            "DisassociateMembers", "DeleteMembers", "StopMonitoringMembers",
          ]
        }
      })
    }
    alerting-tampering = {
      title  = "Alerting pipeline changed"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        detail = {
          eventSource = ["events.amazonaws.com", "sns.amazonaws.com"]
          eventName = [
            "DeleteRule", "DisableRule", "PutRule", "PutTargets", "RemoveTargets",
            "DeleteEventBus", "PutPermission", "RemovePermission",
            "DeleteTopic", "SetTopicAttributes", "Unsubscribe", "SetSubscriptionAttributes",
          ]
        }
      })
    }
    guardrail-changes = {
      title  = "Organization guardrails changed"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        "$or" = [
          {
            detail = {
              eventSource = ["organizations.amazonaws.com"]
              eventName = [
                "AttachPolicy", "DetachPolicy", "UpdatePolicy", "DeletePolicy", "DisablePolicyType",
                "MoveAccount", "RemoveAccountFromOrganization", "LeaveOrganization", "CloseAccount",
                "CreateAccount", "InviteAccountToOrganization",
                "RegisterDelegatedAdministrator", "DeregisterDelegatedAdministrator",
                "EnableAWSServiceAccess", "DisableAWSServiceAccess",
              ]
            }
          },
          {
            detail = {
              eventSource = ["iam.amazonaws.com"]
              eventName   = ["DisableOrganizationsRootCredentialsManagement", "DisableOrganizationsRootSessions"]
            }
          },
        ]
      })
    }
    identity-center-changes = {
      title  = "Identity Center changed"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        "$or" = [
          # Users, groups, memberships, MFA and identity-source settings: any change.
          { detail = { eventSource = ["identitystore.amazonaws.com", "sso-directory.amazonaws.com"] } },
          # Permission sets, assignments, apps: listed, because sso.amazonaws.com
          # also carries routine sign-in events (Authenticate, CreateToken, ...).
          {
            detail = {
              eventSource = ["sso.amazonaws.com"]
              eventName = [
                "CreatePermissionSet", "UpdatePermissionSet", "DeletePermissionSet",
                "AttachManagedPolicyToPermissionSet", "DetachManagedPolicyFromPermissionSet",
                "AttachCustomerManagedPolicyReferenceToPermissionSet",
                "DetachCustomerManagedPolicyReferenceFromPermissionSet",
                "PutInlinePolicyToPermissionSet", "DeleteInlinePolicyFromPermissionSet",
                "PutPermissionsBoundaryToPermissionSet", "DeletePermissionsBoundaryFromPermissionSet",
                "CreateAccountAssignment", "DeleteAccountAssignment",
                "CreateApplication", "CreateApplicationAssignment", "PutApplicationGrant",
                "CreateTrustedTokenIssuer", "UpdateTrustedTokenIssuer",
                "UpdateInstance", "DeleteInstance",
              ]
            }
          },
        ]
      })
    }
    # The access key responder's function and role, plus the forwarders' role
    # (rule changes are already in alerting-tampering). In management, where
    # SCPs can't lock them, this alert is the only guard.
    responder-tampering = {
      title  = "Access key responder changed"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        "$or" = [
          {
            detail = {
              eventSource       = ["lambda.amazonaws.com"]
              eventName         = local.responder_lambda_actions
              requestParameters = { functionName = [{ wildcard = "*access-key-responder*" }] }
            }
          },
          # A blocked attempt (SCP) is logged without the function name
          # (requestParameters: null), so any blocked Lambda change alerts.
          {
            detail = {
              eventSource = ["lambda.amazonaws.com"]
              eventName   = local.responder_lambda_actions
              errorCode   = [{ prefix = "AccessDenied" }]
            }
          },
          {
            detail = {
              eventSource = ["iam.amazonaws.com"]
              eventName = [
                "DeleteRole", "UpdateAssumeRolePolicy", "PutRolePolicy", "DeleteRolePolicy",
                "AttachRolePolicy", "DetachRolePolicy", "PutRolePermissionsBoundary",
              ]
              requestParameters = { roleName = ["access-key-responder", "alert-forwarder"] }
            }
          },
        ]
      })
    }
    iam-users-keys = {
      title  = "IAM user or long-lived credential created"
      format = "api_call"
      pattern = jsonencode({
        "detail-type" = local.api_call
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName   = ["CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateServiceSpecificCredential"]
        }
      })
    }
    access-analyzer-finding = {
      title  = "New external access (Access Analyzer)"
      format = "access_analyzer"
      pattern = jsonencode({
        source        = ["aws.access-analyzer"]
        "detail-type" = ["Access Analyzer Finding"]
        detail        = { status = ["ACTIVE"], isDeleted = [false] }
      })
    }
    guardduty-finding = {
      title  = "GuardDuty finding"
      format = "guardduty"
      # Medium and up (>= 4), first occurrence only: updates to an ongoing
      # finding (every 15 min) stay in the GuardDuty console.
      pattern = jsonencode({
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail        = { severity = [{ numeric = [">=", 4] }], service = { count = [1] } }
      })
    }
  }

  # AssumeRoot is a write event (readOnly: false, verified 2026-10-18), so this
  # opt-in to read-only events isn't needed. Harmless; left as is rather than
  # unlocking ProtectAlerting for no gain.
  read_only_alert_rules = ["assume-root"]
}

resource "aws_cloudwatch_event_rule" "alert" {
  for_each = local.alert_rules

  name           = each.key
  description    = each.value.title
  event_bus_name = aws_cloudwatch_event_bus.org_events.name
  event_pattern  = each.value.pattern
  state          = contains(local.read_only_alert_rules, each.key) ? "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" : "ENABLED"
}

resource "aws_cloudwatch_event_target" "alert" {
  for_each = local.alert_rules

  rule           = aws_cloudwatch_event_rule.alert[each.key].name
  event_bus_name = aws_cloudwatch_event_bus.org_events.name
  arn            = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths    = local.alert_formats[each.value.format].paths
    input_template = "\"[AWS ALERT] ${each.value.title}: ${local.alert_formats[each.value.format].text}\""
  }
}
