# ---------------------------------------------------------------------------
# Edge distribution.
# ---------------------------------------------------------------------------

# Origin Access Control, not the legacy Origin Access Identity. OAC supports
# SSE-KMS and all regions, signs with SigV4, and is what AWS recommends for new
# distributions. Knowing the difference is a standard interview question.
resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${var.name}-oac"
  description                       = "Signs CloudFront's requests to the private S3 origin"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "selected" {
  name = var.cache_policy_name
}

# For the /api/* behavior: never cache, and forward everything EXCEPT the Host
# header -- API Gateway routes on Host, so forwarding the CloudFront domain
# would 403 every request.
data "aws_cloudfront_cache_policy" "api_no_cache" {
  count = var.api_origin_domain == null ? 0 : 1
  name  = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "api_all_viewer" {
  count = var.api_origin_domain == null ? 0 : 1
  name  = "Managed-AllViewerExceptHostHeader"
}

# Free, visible security wins the prototype left on the table. These appear in
# every response and show up immediately in a securityheaders.io scan, which
# makes them worth a screenshot in the README.
resource "aws_cloudfront_response_headers_policy" "site" {
  name = "${var.name}-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
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
      content_security_policy = var.content_security_policy
      override                = true
    }
  }
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  comment             = "${var.name} - WAF Ops Platform edge"
  default_root_object = "index.html"
  price_class         = "PriceClass_100" # NA + EU only; cheapest class
  tags                = var.tags

  # CloudFront takes the Web ACL *ARN* here despite the argument being named
  # web_acl_id. The ACL must be CLOUDFRONT-scoped and live in us-east-1.
  web_acl_id = var.web_acl_arn

  origin {
    # The REST endpoint (bucket.s3.region.amazonaws.com), NOT the website
    # endpoint. Only the REST endpoint works with OAC and a private bucket.
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  dynamic "origin" {
    for_each = var.api_origin_domain == null ? [] : [var.api_origin_domain]
    content {
      domain_name = origin.value
      origin_id   = "api-origin"

      custom_origin_config {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }

      # Proof-of-path: the API rejects requests without this header, closing
      # the direct execute-api bypass around the WAF.
      custom_header {
        name  = "x-origin-verify"
        value = var.origin_verify_secret
      }
    }
  }

  default_cache_behavior {
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "redirect-to-https"

    # All methods are allowed so the attack suite can exercise POST/PUT/DELETE
    # against the origin_check rule. A static site would normally allow only
    # GET/HEAD.
    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    compress = true

    # Modern policy attachments. The prototype used the legacy forwarded_values
    # block, which AWS has deprecated in favour of these.
    cache_policy_id            = data.aws_cloudfront_cache_policy.selected.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.site.id
  }

  dynamic "ordered_cache_behavior" {
    for_each = var.api_origin_domain == null ? [] : ["api"]
    content {
      path_pattern           = "/api/*"
      target_origin_id       = "api-origin"
      viewer_protocol_policy = "https-only"

      allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods  = ["GET", "HEAD"]
      compress        = true

      cache_policy_id            = data.aws_cloudfront_cache_policy.api_no_cache[0].id
      origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.api_all_viewer[0].id
      response_headers_policy_id = aws_cloudfront_response_headers_policy.site.id
    }
  }

  # SPA deep links: client-side routes like /trip/42 have no S3 key, so the
  # origin's miss must come back as index.html. Only 404 is mapped, NEVER 403:
  # CloudFront applies custom error pages to WAF-blocked responses too, so a
  # 403 mapping would turn every WAF block into a 200 and falsify the attack
  # suite's verdicts. The bucket policy grants CloudFront s3:ListBucket
  # precisely so missing keys surface as 404 rather than 403.
  dynamic "custom_error_response" {
    for_each = var.spa_fallback ? [404] : []
    content {
      error_code         = custom_error_response.value
      response_code      = 200
      response_page_path = "/index.html"
    }
  }

  restrictions {
    geo_restriction {
      # Geography is handled by the WAF geo rule, not here, so that blocks are
      # logged and countable rather than silently dropped at the edge.
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true

    # minimum_protocol_version cannot be raised while using the default
    # *.cloudfront.net certificate -- CloudFront pins it. Enforcing TLS 1.2+
    # requires a custom domain with an ACM certificate. See open decision #7 in
    # docs/PLAN.md.
  }

  lifecycle {
    precondition {
      condition     = var.web_acl_arn != null && var.web_acl_arn != ""
      error_message = "This distribution must not be created without a Web ACL. An unprotected origin is the defect this project exists to fix."
    }
  }
}
