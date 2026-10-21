data "aws_ssoadmin_instances" "this" {}

locals {
  sso_instance_arn  = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]
}

# --- People -------------------------------------------------------------

resource "aws_identitystore_user" "nojus" {
  identity_store_id = local.identity_store_id
  user_name         = "nojus"
  display_name      = "Nojus N"

  name {
    given_name  = "Nojus"
    family_name = "N"
  }

  emails {
    value   = var.sso_user_email
    type    = "work"
    primary = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_identitystore_group" "admins" {
  identity_store_id = local.identity_store_id
  display_name      = "admins"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_identitystore_group_membership" "nojus_admins" {
  identity_store_id = local.identity_store_id
  group_id          = aws_identitystore_group.admins.group_id
  member_id         = aws_identitystore_user.nojus.user_id

  lifecycle {
    prevent_destroy = true
  }
}

# --- Permission sets ----------------------------------------------------

resource "aws_ssoadmin_permission_set" "admin" {
  instance_arn     = local.sso_instance_arn
  name             = "AdministratorAccess"
  session_duration = "PT1H"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssoadmin_managed_policy_attachment" "admin" {
  #checkov:skip=CKV_AWS_274:single admin, SSO + MFA + 1h sessions; daily reads via SecurityAudit
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

  lifecycle {
    prevent_destroy = true
  }
}

# Read-only audit access for scanners (Prowler): reads configuration, not
# data — unlike ReadOnlyAccess, it can't download S3 objects such as state.
resource "aws_ssoadmin_permission_set" "audit" {
  instance_arn     = local.sso_instance_arn
  name             = "SecurityAudit"
  session_duration = "PT4H" # read-only: long scans OK, can't change anything
}

resource "aws_ssoadmin_managed_policy_attachment" "audit_security_audit" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.audit.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_ssoadmin_managed_policy_attachment" "audit_view_only" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.audit.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# --- Assignments: group "admins" ---------------------------------------

resource "aws_ssoadmin_account_assignment" "admins_admin_management" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn
  principal_type     = "GROUP"
  principal_id       = aws_identitystore_group.admins.group_id
  target_type        = "AWS_ACCOUNT"
  target_id          = aws_organizations_account.management.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssoadmin_account_assignment" "admins_admin_live" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn
  principal_type     = "GROUP"
  principal_id       = aws_identitystore_group.admins.group_id
  target_type        = "AWS_ACCOUNT"
  target_id          = aws_organizations_account.live.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssoadmin_account_assignment" "admins_admin_lab" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn
  principal_type     = "GROUP"
  principal_id       = aws_identitystore_group.admins.group_id
  target_type        = "AWS_ACCOUNT"
  target_id          = aws_organizations_account.lab.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssoadmin_account_assignment" "admins_admin_security" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn
  principal_type     = "GROUP"
  principal_id       = aws_identitystore_group.admins.group_id
  target_type        = "AWS_ACCOUNT"
  target_id          = aws_organizations_account.security.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssoadmin_account_assignment" "admins_audit" {
  for_each = {
    management = aws_organizations_account.management.id
    live       = aws_organizations_account.live.id
    lab        = aws_organizations_account.lab.id
    security   = aws_organizations_account.security.id
  }

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.audit.arn
  principal_type     = "GROUP"
  principal_id       = aws_identitystore_group.admins.group_id
  target_type        = "AWS_ACCOUNT"
  target_id          = each.value
}
