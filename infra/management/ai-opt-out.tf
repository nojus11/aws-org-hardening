# Org-wide: AWS may not store or use our content to improve its AI
# services (Rekognition, Textract, Transcribe, …). "default" = every AI
# service; "@@assign" = set this value; "@@operators_allowed_for_child_policies"
# = ["@@none"] locks it, so a policy on an OU or account can't override it.
resource "aws_organizations_policy" "ai_opt_out" {
  name        = "OptOutOfAIServicesDataUse"
  description = "Opt all accounts out of AI service content use"
  type        = "AISERVICES_OPT_OUT_POLICY"
  content = jsonencode({
    services = {
      "@@operators_allowed_for_child_policies" = ["@@none"]
      default = {
        "@@operators_allowed_for_child_policies" = ["@@none"]
        opt_out_policy = {
          "@@operators_allowed_for_child_policies" = ["@@none"]
          "@@assign"                               = "optOut"
        }
      }
    }
  })

  # The policy type must be enabled in the org first
  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "ai_opt_out_root" {
  policy_id = aws_organizations_policy.ai_opt_out.id
  target_id = aws_organizations_organization.this.roots[0].id
}
