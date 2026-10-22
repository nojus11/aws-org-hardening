# Declarative policy: AWS's EC2 service itself holds these settings in the
# member accounts, for every API (current and future), so no admin can change
# them. The account-baseline module sets the same values; this makes them
# untouchable. Values match the module, so Terraform sees no drift.
resource "aws_organizations_policy" "ec2_baseline" {
  name        = "EC2Baseline"
  description = "Member accounts: serial console off, no public AMIs/snapshots, IMDSv2 by default"
  type        = "DECLARATIVE_POLICY_EC2"
  content = jsonencode({
    ec2_attributes = {
      serial_console_access        = { status = { "@@assign" = "disabled" } }
      image_block_public_access    = { state = { "@@assign" = "block_new_sharing" } }
      snapshot_block_public_access = { state = { "@@assign" = "block_all_sharing" } }
      instance_metadata_defaults = {
        http_tokens                 = { "@@assign" = "required" }
        http_put_response_hop_limit = { "@@assign" = "-1" } # -1 = no preference
        http_endpoint               = { "@@assign" = "no_preference" }
        instance_metadata_tags      = { "@@assign" = "no_preference" }
      }
    }
  })

  depends_on = [aws_organizations_organization.this] # the policy type must be enabled first

  lifecycle {
    prevent_destroy = true
  }
}

# Rolled out lab first (tested: admin changes denied), then live + security.
resource "aws_organizations_policy_attachment" "ec2_baseline" {
  for_each = {
    lab      = aws_organizations_organizational_unit.lab.id
    live     = aws_organizations_organizational_unit.live.id
    security = aws_organizations_organizational_unit.security.id
  }

  policy_id = aws_organizations_policy.ec2_baseline.id
  target_id = each.value
}
