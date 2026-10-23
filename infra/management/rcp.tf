# Resource control policy: limits who can use resources in member accounts,
# whatever their own policies say. Based on AWS's identity-perimeter example
# (aws-samples/data-perimeter-policy-examples), trimmed: no third-party
# accounts, no tag opt-out (anyone who can tag a resource could exempt it).
# RCPs never apply to management's resources or to service-linked roles.
resource "aws_organizations_policy" "data_perimeter" {
  name        = "DataPerimeter"
  description = "Member resources: my org, AWS services working for my org, my GitHub, HTTPS only"
  type        = "RESOURCE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceOrgIdentities"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:*", "kms:*", "sqs:*", "secretsmanager:*", "logs:*", "dynamodb:*", "ecr:*",
          "sts:AssumeRole", "sts:DecodeAuthorizationMessage", "sts:GetAccessKeyInfo",
          "sts:GetFederationToken", "sts:GetServiceBearerToken", "sts:GetSessionToken", "sts:SetContext",
        ]
        Resource = "*"
        Condition = {
          StringNotEqualsIfExists = { "aws:PrincipalOrgID" = aws_organizations_organization.this.id }
          BoolIfExists            = { "aws:PrincipalIsAWSService" = "false" }
        }
      },
      {
        Sid       = "EnforceGitHubOIDCOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sts:AssumeRoleWithWebIdentity"
        Resource  = "*"
        Condition = { Null = { "token.actions.githubusercontent.com:sub" = "true" } }
      },
      {
        Sid       = "EnforceMyGitHubOwner"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sts:AssumeRoleWithWebIdentity"
        Resource  = "*"
        Condition = {
          StringNotLike = { "token.actions.githubusercontent.com:sub" = "repo:nojus11@263101606/*" }
          Null          = { "token.actions.githubusercontent.com:sub" = "false" }
        }
      },
      {
        Sid       = "EnforceConfusedDeputyProtection"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:*", "sts:*", "kms:*", "sqs:*", "secretsmanager:*", "logs:*", "dynamodb:*", "ecr:*"]
        Resource  = "*"
        Condition = {
          StringNotEqualsIfExists = { "aws:SourceOrgID" = aws_organizations_organization.this.id }
          Null                    = { "aws:SourceAccount" = "false" }
          Bool                    = { "aws:PrincipalIsAWSService" = "true" }
        }
      },
      {
        Sid       = "EnforceSecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:*", "sts:*", "kms:*", "sqs:*", "secretsmanager:*"]
        Resource  = "*"
        Condition = { BoolIfExists = { "aws:SecureTransport" = "false" } }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

# Rolled out lab → live → security, testing each (AWS: widen step by step).
# Lab experiments needing outside access: detach lab for the experiment.
resource "aws_organizations_policy_attachment" "data_perimeter" {
  for_each = {
    lab        = aws_organizations_organizational_unit.lab.id
    live       = aws_organizations_organizational_unit.live.id
    security   = aws_organizations_organizational_unit.security.id
    quarantine = aws_organizations_organizational_unit.quarantine.id
  }

  policy_id = aws_organizations_policy.data_perimeter.id
  target_id = each.value
}
