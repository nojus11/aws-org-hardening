# Neither domain sends or receives email (yet), so say so in DNS: a null MX
# (RFC 7505: accepts no mail), SPF that allows no sender, and DMARC reject.
# Receivers then drop phishing that pretends to come from these domains.
# nojusniuklys.com: replace with the real records when the custom inbox is
# set up (notes/website.md, "Later").
locals {
  no_mail_zones = {
    nojusniuklys = aws_route53_zone.nojusniuklys
    notavirus    = aws_route53_zone.notavirus
  }
}

resource "aws_route53_record" "null_mx" {
  for_each = local.no_mail_zones

  zone_id = each.value.zone_id
  name    = each.value.name
  type    = "MX"
  ttl     = 3600
  records = ["0 ."]
}

resource "aws_route53_record" "spf_no_senders" {
  for_each = local.no_mail_zones

  zone_id = each.value.zone_id
  name    = each.value.name
  type    = "TXT"
  ttl     = 3600
  records = ["v=spf1 -all"]
}

resource "aws_route53_record" "dmarc_reject" {
  for_each = local.no_mail_zones

  zone_id = each.value.zone_id
  name    = "_dmarc.${each.value.name}"
  type    = "TXT"
  ttl     = 3600
  records = ["v=DMARC1; p=reject"]
}
