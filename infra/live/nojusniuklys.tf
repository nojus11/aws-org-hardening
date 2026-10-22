resource "aws_route53_zone" "nojusniuklys" {
  #checkov:skip=CKV2_AWS_38:no DNSSEC for now: KMS key cost, a mistake takes the domain offline; low value for a static site; may revisit
  #checkov:skip=CKV2_AWS_39:Route 53 query logging off: logs show DNS resolvers, not visitors; low value for a personal domain
  name = "nojusniuklys.com"

  lifecycle {
    # A new zone gets new nameservers: the domain would go dark until
    # Porkbun is updated and the change spreads.
    prevent_destroy = true
  }
}

output "nojusniuklys_name_servers" {
  description = "Set these 4 as the nameservers at Porkbun"
  value       = aws_route53_zone.nojusniuklys.name_servers
}

# Only Amazon may issue certificates for this domain, and nobody may
# issue wildcards. Covers www too: CAA is inherited by subdomains.
resource "aws_route53_record" "nojusniuklys_caa" {
  zone_id = aws_route53_zone.nojusniuklys.zone_id
  name    = "nojusniuklys.com"
  type    = "CAA"
  ttl     = 3600
  records = [
    "0 issue \"amazon.com\"",
    "0 issuewild \";\"",
  ]
}

resource "aws_acm_certificate" "nojusniuklys" {
  domain_name               = "nojusniuklys.com"
  subject_alternative_names = ["www.nojusniuklys.com"]
  validation_method         = "DNS"

  lifecycle {
    # On replacement, issue the new certificate before deleting the old
    # one, so CloudFront never points at a deleted certificate.
    create_before_destroy = true
  }
}

# One validation CNAME per name on the certificate
resource "aws_route53_record" "nojusniuklys_cert_validation" {
  for_each = {
    for o in aws_acm_certificate.nojusniuklys.domain_validation_options : o.domain_name => o
  }

  zone_id = aws_route53_zone.nojusniuklys.zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 300
}

# Not an AWS resource: makes apply wait until ACM says ISSUED
resource "aws_acm_certificate_validation" "nojusniuklys" {
  certificate_arn         = aws_acm_certificate.nojusniuklys.arn
  validation_record_fqdns = [for r in aws_route53_record.nojusniuklys_cert_validation : r.fqdn]
}

# Live's own account ID, from AWS ("who am I?") — no variable needed
data "aws_caller_identity" "current" {}

# Site files. Private: only CloudFront reads it (OAC + bucket policy below).
resource "aws_s3_bucket" "nojusniuklys_site" {
  #checkov:skip=CKV_AWS_145:SSE-S3 accepted: public site content; a CMK adds cost and a CloudFront key grant, no gain
  #checkov:skip=CKV_AWS_21:no versioning: source in git, a re-upload restores the site
  #checkov:skip=CKV2_AWS_61:no lifecycle: no versions or temporary objects to expire
  #checkov:skip=CKV_AWS_144:single-region by design (RestrictRegions SCP)
  #checkov:skip=CKV2_AWS_62:no event notifications needed
  #checkov:skip=CKV_AWS_18:only CloudFront reads the bucket; access logging belongs at CloudFront (not set up yet)
  bucket = "nojusniuklys-site-${data.aws_caller_identity.current.account_id}"
}

# Secure on its own — never rely on account-level Block Public Access.
resource "aws_s3_bucket_public_access_block" "nojusniuklys_site" {
  bucket = aws_s3_bucket.nojusniuklys_site.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# CloudFront signs every request to the bucket; the bucket policy below
# allows only this distribution.
resource "aws_cloudfront_origin_access_control" "nojusniuklys" {
  name                              = "nojusniuklys-site"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_distribution" "nojusniuklys" {
  #checkov:skip=CKV_AWS_374:public site, open to every country
  #checkov:skip=CKV_AWS_310:single origin by design (one region only)
  #checkov:skip=CKV_AWS_68:no WAF: GET/HEAD-only static site, no backend; ≥ $5/month; Shield Standard included
  #checkov:skip=CKV2_AWS_47:no WAF (see CKV_AWS_68), and no Java backend for Log4j
  #checkov:skip=CKV_AWS_86:access logging deferred, not accepted: options and cost still to research
  enabled             = true
  aliases             = ["nojusniuklys.com", "www.nojusniuklys.com"]
  default_root_object = "index.html"
  http_version        = "http2and3"
  is_ipv6_enabled     = true
  price_class         = "PriceClass_100" # North America + Europe edges only

  origin {
    origin_id                = "site-bucket"
    domain_name              = aws_s3_bucket.nojusniuklys_site.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.nojusniuklys.id
  }

  default_cache_behavior {
    target_origin_id           = "site-bucket"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.nojusniuklys.id
    compress                   = true
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.nojusniuklys.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

output "nojusniuklys_cloudfront_domain" {
  value = aws_cloudfront_distribution.nojusniuklys.domain_name
}

# Only this distribution may read the files; nothing over plain HTTP.
resource "aws_s3_bucket_policy" "nojusniuklys_site" {
  bucket = aws_s3_bucket.nojusniuklys_site.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontRead"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.nojusniuklys_site.arn}/*"
        Condition = {
          StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.nojusniuklys.arn }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.nojusniuklys_site.arn, "${aws_s3_bucket.nojusniuklys_site.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

# Security headers on every response. The site runs no JavaScript, so the
# CSP allows no scripts at all.
resource "aws_cloudfront_response_headers_policy" "nojusniuklys" {
  #checkov:skip=CKV_AWS_259:HSTS preload deliberately off: the browser preload list is very hard to leave
  name = "nojusniuklys-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000 # 1 year
      include_subdomains         = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    content_security_policy {
      content_security_policy = join("; ", [
        "default-src 'none'",
        # 'unsafe-inline': inline styles on the placeholder pages; drop it
        # with the content rework
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
        "font-src https://fonts.gstatic.com",
        "img-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ])
      override = true
    }
  }
}

# nojusniuklys.com + www → CloudFront: every name × A (IPv4) and AAAA (IPv6)
resource "aws_route53_record" "nojusniuklys_site" {
  for_each = {
    for pair in setproduct(aws_cloudfront_distribution.nojusniuklys.aliases, ["A", "AAAA"]) :
    "${pair[0]} ${pair[1]}" => pair
  }

  zone_id = aws_route53_zone.nojusniuklys.zone_id
  name    = each.value[0]
  type    = each.value[1]

  alias {
    name                   = aws_cloudfront_distribution.nojusniuklys.domain_name
    zone_id                = aws_cloudfront_distribution.nojusniuklys.hosted_zone_id
    evaluate_target_health = false
  }
}

# GitHub Actions deploy: only main of nojus11/nojusniuklys.com; only
# upload/delete site files and clear the cache. If stolen: a defaced
# site, nothing more.
resource "aws_iam_role" "nojusniuklys_deploy" {
  name = "nojusniuklys-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = module.baseline.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          # New-format subject (repos created after 2026-07-15): the owner and
          # repo IDs are never reused, so a recreated repo with the same name
          # can't match.
          "token.actions.githubusercontent.com:sub" = "repo:nojus11@263101606/nojusniuklys.com@1427531730:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "nojusniuklys_deploy" {
  name = "deploy-site"
  role = aws_iam_role.nojusniuklys_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CompareFiles"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.nojusniuklys_site.arn
      },
      {
        Sid      = "WriteFiles"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.nojusniuklys_site.arn}/*"
      },
      {
        Sid      = "ClearCache"
        Effect   = "Allow"
        Action   = "cloudfront:CreateInvalidation"
        Resource = aws_cloudfront_distribution.nojusniuklys.arn
      },
    ]
  })
}

output "nojusniuklys_deploy_role_arn" {
  description = "Goes in the GitHub workflow (not a secret)"
  value       = aws_iam_role.nojusniuklys_deploy.arn
}
