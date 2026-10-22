# The GitHub OIDC provider moved into the baseline module (every account
# has one now, for the drift-check role). Same resource, new address.
moved {
  from = aws_iam_openid_connect_provider.github
  to   = module.baseline.aws_iam_openid_connect_provider.github
}
