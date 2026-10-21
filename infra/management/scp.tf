resource "aws_organizations_policy" "deny_leave_and_close" {
  name        = "DenyLeaveAndCloseAccount"
  description = "Prevents member accounts from leaving the organization and self closure"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Deny"
      Action = [
        "organizations:LeaveOrganization",
        "account:CloseAccount",
      ]
      Resource = "*"
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy_attachment" "deny_leave_and_close_root" {
  policy_id = aws_organizations_policy.deny_leave_and_close.id
  target_id = aws_organizations_organization.this.roots[0].id

  lifecycle {
    prevent_destroy = true
  }
}

# Protect the CloudTrail log archive from every identity in the security
# account, admins included. CloudTrail itself (a service principal) is not
# affected by SCPs, so log delivery keeps working. To change the bucket on
# purpose: detach this policy from management first (logged in CloudTrail).
resource "aws_organizations_policy" "protect_log_archive" {
  name        = "ProtectLogArchive"
  description = "Deny tampering with the CloudTrail log bucket and its KMS key"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyLogArchiveTampering"
        Effect = "Deny"
        Action = [
          # the log files
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:PutObjectRetention",
          "s3:BypassGovernanceRetention",
          # the bucket's protections
          "s3:DeleteBucket",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:PutBucketObjectLockConfiguration",
          "s3:PutBucketVersioning",
          "s3:PutLifecycleConfiguration",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
        ]
        Resource = [
          "arn:aws:s3:::cloudtrail-logs-${local.security_account_id}",
          "arn:aws:s3:::cloudtrail-logs-${local.security_account_id}/*",
        ]
      },
      {
        # The key that encrypts the logs (infra/security/log-archive-key.tf):
        # disabling or deleting it would stop log delivery org-wide.
        Sid    = "DenyLogKeyTampering"
        Effect = "Deny"
        Action = [
          "kms:DisableKey", "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy",
          "kms:DisableKeyRotation", "kms:CreateGrant",
        ]
        Resource = "arn:aws:kms:us-east-1:${local.security_account_id}:key/${var.log_archive_kms_key_id}"
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy_attachment" "protect_log_archive_security" {
  policy_id = aws_organizations_policy.protect_log_archive.id
  target_id = aws_organizations_organizational_unit.security.id

  lifecycle {
    prevent_destroy = true
  }
}

# Protect the alerting pipeline (forwarders, their role, the hub and its email
# topic) from every identity in the member accounts, admins included.
# EventBridge itself and service-linked roles are not affected by SCPs.
# To change any of it on purpose: detach this policy from management first,
# which itself triggers a "guardrails changed" alert.
resource "aws_organizations_policy" "protect_alerting" {
  name        = "ProtectAlerting"
  description = "Deny tampering with the alerting forwarders, hub and topic"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyRuleTampering"
        Effect = "Deny"
        Action = ["events:DeleteRule", "events:DisableRule", "events:PutRule", "events:PutTargets", "events:RemoveTargets"]
        Resource = [
          "arn:aws:events:*:*:rule/forward-*",                                # spokes: every account and region
          "arn:aws:events:us-east-1:${local.security_account_id}:rule/org-security-events/*", # hub rules
        ]
      },
      {
        Sid      = "DenyHubBusDeletion"
        Effect   = "Deny"
        Action   = "events:DeleteEventBus"
        Resource = "arn:aws:events:us-east-1:${local.security_account_id}:event-bus/org-security-events"
      },
      {
        # No resource-level permissions exist for these: limit to security.
        Sid       = "DenyBusPolicyChangesInSecurity"
        Effect    = "Deny"
        Action    = ["events:PutPermission", "events:RemovePermission"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:PrincipalAccount" = local.security_account_id } }
      },
      {
        Sid    = "DenyTopicTampering"
        Effect = "Deny"
        Action = [
          "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:AddPermission", "sns:RemovePermission",
          "sns:Unsubscribe", "sns:SetSubscriptionAttributes", "sns:PutDataProtectionPolicy",
        ]
        Resource = "arn:aws:sns:us-east-1:${local.security_account_id}:security-alerts"
      },
      {
        Sid    = "DenyForwarderRoleTampering"
        Effect = "Deny"
        Action = [
          "iam:DeleteRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary",
        ]
        Resource = "arn:aws:iam::*:role/alert-forwarder"
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy_attachment" "protect_alerting_root" {
  policy_id = aws_organizations_policy.protect_alerting.id
  target_id = aws_organizations_organization.this.roots[0].id

  lifecycle {
    prevent_destroy = true
  }
}

# Member accounts work in us-east-1 only: an attacker can't hide resources
# (e.g. crypto-miners) in unwatched regions. Global actions are exempt; the
# list mirrors AWS Control Tower's Region deny control (CT.MULTISERVICE.PV.1,
# checked 2026-10-18). Exceptions:
# - SecurityAudit role: everywhere (read-only by design; scans must see all regions)
# - security's admin role: GuardDuty + EventBridge everywhere (17-region
#   GuardDuty and finding forwarders, managed by Terraform)
# - alert-forwarder role: EventBridge (delivers findings to the hub)
# To change: detach from management first (alerts), like the others.
locals {
  region_global_actions = [
    "a4b:*", "access-analyzer:*", "account:*", "acm:*", "activate:*", "artifact:*",
    "aws-marketplace-management:*", "aws-marketplace:*", "aws-portal:*", "billing:*",
    "billingconductor:*", "budgets:*", "ce:*", "chatbot:*", "chime:*", "cloudfront:*",
    "cloudtrail:LookupEvents", "compute-optimizer:*", "config:*", "consoleapp:*",
    "consolidatedbilling:*", "cur:*", "datapipeline:GetAccountLimits", "devicefarm:*",
    "directconnect:*", "ec2:DescribeRegions", "ec2:DescribeTransitGateways",
    "ec2:DescribeVpnGateways", "ecr-public:*", "fms:*", "freetier:*", "globalaccelerator:*",
    "health:*", "iam:*", "importexport:*", "invoicing:*", "iq:*", "kms:*",
    "license-manager:ListReceivedLicenses", "lightsail:Get*", "mobileanalytics:*",
    "networkmanager:*", "notifications-contacts:*", "notifications:*", "organizations:*",
    "payments:*", "pricing:*", "quicksight:DescribeAccountSubscription",
    "resource-explorer-2:*", "route53-recovery-cluster:*", "route53-recovery-control-config:*",
    "route53-recovery-readiness:*", "route53:*", "route53domains:*",
    "s3:CreateMultiRegionAccessPoint", "s3:DeleteMultiRegionAccessPoint",
    "s3:DescribeMultiRegionAccessPointOperation", "s3:GetAccountPublicAccessBlock",
    "s3:GetBucketLocation", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
    "s3:GetMultiRegionAccessPoint", "s3:GetMultiRegionAccessPointPolicy",
    "s3:GetMultiRegionAccessPointPolicyStatus", "s3:GetStorageLensConfiguration",
    "s3:GetStorageLensDashboard", "s3:ListAllMyBuckets", "s3:ListMultiRegionAccessPoints",
    "s3:ListStorageLensConfigurations", "s3:PutAccountPublicAccessBlock",
    "s3:PutMultiRegionAccessPointPolicy", "savingsplans:*", "shield:*", "sso:*", "sts:*",
    "support:*", "supportapp:*", "supportplans:*", "sustainability:*", "tag:GetResources",
    "tax:*", "trustedadvisor:*", "vendor-insights:ListEntitledSecurityProfiles",
    "waf-regional:*", "waf:*", "wafv2:*",
  ]
  audit_role_arn          = "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_SecurityAudit_*"
  security_admin_role_arn = "arn:aws:iam::${local.security_account_id}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_*"
}

resource "aws_organizations_policy" "restrict_regions" {
  name        = "RestrictRegions"
  description = "Member accounts: us-east-1 only (global actions and named roles exempt)"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Everything regional, outside us-east-1. GuardDuty + EventBridge are
        # left to the next statement, which allows them for named roles only.
        Sid       = "DenyOutsideUsEast1"
        Effect    = "Deny"
        NotAction = concat(local.region_global_actions, ["guardduty:*", "events:*"])
        Resource  = "*"
        Condition = {
          StringNotEquals = { "aws:RequestedRegion" = ["us-east-1"] }
          ArnNotLike      = { "aws:PrincipalARN" = [local.audit_role_arn] }
        }
      },
      {
        Sid      = "DenyGuardDutyEventBridgeOutsideUsEast1"
        Effect   = "Deny"
        Action   = ["guardduty:*", "events:*"]
        Resource = "*"
        Condition = {
          StringNotEquals = { "aws:RequestedRegion" = ["us-east-1"] }
          ArnNotLike = {
            "aws:PrincipalARN" = [
              local.audit_role_arn,
              local.security_admin_role_arn,
              "arn:aws:iam::*:role/alert-forwarder",
            ]
          }
        }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy_attachment" "restrict_regions_root" {
  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = aws_organizations_organization.this.roots[0].id

  lifecycle {
    prevent_destroy = true
  }
}

# Cost guardrail: member accounts can only launch small, burstable EC2
# instance types, so a stolen session can't start $50+/hour GPU machines.
# Families are listed by name: "t*" would also allow trn1 (Trainium).
# Attached to the three OUs, not the root, to keep a root SCP slot free
# (max 5 per target). Covers direct EC2 launches only; compute started by
# other services (SageMaker, Batch, EKS) isn't covered: budget alerts and
# GuardDuty are the backstop there.
resource "aws_organizations_policy" "restrict_instance_types" {
  name        = "RestrictInstanceTypes"
  description = "Member accounts: burstable EC2 instance types only (t2/t3/t3a/t4g)"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenyNonBurstableInstances"
      Effect   = "Deny"
      Action   = "ec2:RunInstances"
      Resource = "arn:aws:ec2:*:*:instance/*"
      Condition = {
        StringNotLike = { "ec2:InstanceType" = ["t2.*", "t3.*", "t3a.*", "t4g.*"] }
      }
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy_attachment" "restrict_instance_types" {
  for_each = {
    live     = aws_organizations_organizational_unit.live.id
    lab      = aws_organizations_organizational_unit.lab.id
    security = aws_organizations_organizational_unit.security.id
  }

  policy_id = aws_organizations_policy.restrict_instance_types.id
  target_id = each.value

  lifecycle {
    prevent_destroy = true
  }
}

# Protect the account baseline (infra/modules/account-baseline) from every
# identity in the member accounts, admins included: nobody can quietly undo
# encryption, public-access blocks, Config or Access Analyzer. Lab keeps its
# deliberate exceptions (S3/VPC Block Public Access, default VPC).
# Attached to the three OUs (root SCP slots are nearly full).
# To change on purpose: detach first (alerts), like the others.
locals {
  lab_account_id = aws_organizations_account.lab.id
}

resource "aws_organizations_policy" "protect_baseline" {
  name        = "ProtectBaseline"
  description = "Deny undoing the account baseline (lab keeps its public-access exceptions)"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyBaselineChanges"
        Effect = "Deny"
        Action = [
          "ec2:DisableEbsEncryptionByDefault", "ec2:ModifyEbsDefaultKmsKeyId", "ec2:ResetEbsDefaultKmsKeyId",
          "ec2:DisableSnapshotBlockPublicAccess", "ec2:EnableSnapshotBlockPublicAccess",
          "ec2:ModifyInstanceMetadataDefaults",
          "iam:UpdateAccountPasswordPolicy", "iam:DeleteAccountPasswordPolicy",
          "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
          "config:PutConfigurationRecorder", "config:DeleteDeliveryChannel", "config:PutDeliveryChannel",
          "access-analyzer:DeleteAnalyzer", "access-analyzer:CreateArchiveRule",
          "access-analyzer:UpdateArchiveRule",
          "ssm:UpdateServiceSetting", "ssm:ResetServiceSetting",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyPublicAccessChangesOutsideLab"
        Effect = "Deny"
        Action = [
          "s3:PutAccountPublicAccessBlock",
          "ec2:ModifyVpcBlockPublicAccessOptions", "ec2:CreateVpcBlockPublicAccessExclusion",
          "ec2:CreateDefaultVpc",
        ]
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:PrincipalAccount" = local.lab_account_id } }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy_attachment" "protect_baseline" {
  for_each = {
    live     = aws_organizations_organizational_unit.live.id
    lab      = aws_organizations_organizational_unit.lab.id
    security = aws_organizations_organizational_unit.security.id
  }

  policy_id = aws_organizations_policy.protect_baseline.id
  target_id = each.value

  lifecycle {
    prevent_destroy = true
  }
}
