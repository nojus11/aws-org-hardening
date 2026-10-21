# notavirus.click: domain held for a future site; nothing served.

resource "aws_route53_zone" "notavirus" {
  #checkov:skip=CKV2_AWS_38:no DNSSEC: domain held, nothing served
  #checkov:skip=CKV2_AWS_39:Route 53 query logging off: logs show DNS resolvers, not visitors; low value for a personal domain
  name    = "notavirus.click"
  comment = "HostedZone created by Route53 Registrar"

  lifecycle {
    # A new zone gets new nameservers: the domain would point at nothing.
    prevent_destroy = true
  }
}

# Registered with Route 53 Domains in this account. Removing this from
# Terraform never deletes the registration, it only stops managing it.
resource "aws_route53domains_registered_domain" "notavirus" {
  domain_name   = "notavirus.click"
  auto_renew    = true
  transfer_lock = true # blocks moving the domain to another registrar
}
