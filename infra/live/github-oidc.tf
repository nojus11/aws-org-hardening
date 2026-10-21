# Lets GitHub Actions sign in with short-lived tokens instead of stored
# keys. One per account; each deploy role limits which repo and branch.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}
