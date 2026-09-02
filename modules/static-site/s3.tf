# ---------------------------------------------------------------------------
# Origin bucket.
#
# THIS FILE IS THE FIX FOR THE PROTOTYPE'S CENTRAL DEFECT.
#
# The prototype disabled all four Block Public Access settings, attached a
# bucket policy granting s3:GetObject to Principal "*", turned on S3 static
# website hosting, and then pointed CloudFront at it with an empty
# OriginAccessIdentity. The bucket was therefore readable at its own S3 URL,
# so anyone could serve the site while skipping CloudFront and the WAF
# entirely. For a project whose whole claim is "a WAF protects this site",
# that invalidated the claim.
#
# Three things below prevent it, and all three are load-bearing:
#   1. Block Public Access fully on, so no policy can ever make it public.
#   2. Origin Access Control, so CloudFront signs its origin requests.
#   3. An aws:SourceArn condition pinning access to THIS distribution.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "site" {
  bucket        = "${var.name}-origin-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # ephemeral by design; see docs/COST-MODEL.md
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket = aws_s3_bucket.site.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "site" {
  bucket = aws_s3_bucket.site.id

  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs disabled entirely
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "site" {
  bucket = aws_s3_bucket.site.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# NOTE: deliberately absent -- aws_s3_bucket_website_configuration.
# The S3 *website* endpoint cannot be used with Origin Access Control and
# requires a public bucket. That requirement is exactly how the prototype ended
# up public. This module uses the REST endpoint instead (see cloudfront.tf).

# The only principal permitted to read objects is the CloudFront service, and
# only when acting on behalf of this specific distribution.
#
# Without the aws:SourceArn condition the policy would trust the CloudFront
# service generally, meaning any distribution in any AWS account could read the
# bucket. That is a real, published misconfiguration class -- the condition is
# the part that makes this tight.
data "aws_iam_policy_document" "site" {
  statement {
    sid    = "AllowCloudFrontServicePrincipalReadOnly"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site.arn]
    }
  }

  # ListBucket makes S3 answer 404 (not 403) for keys that do not exist, which
  # the SPA fallback in cloudfront.tf depends on: only 404 can be mapped to
  # index.html, because a 403 mapping would also rewrite WAF block responses.
  statement {
    sid    = "AllowCloudFrontListForCleanNotFound"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.site.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = data.aws_iam_policy_document.site.json

  # Block Public Access must be in place before any policy is attached.
  depends_on = [aws_s3_bucket_public_access_block.site]
}

# Everything under content_dir is uploaded. Defaults to the module's placeholder
# site/ so the module stands alone; point it at a real build output (e.g. a Vite
# dist/) to serve an application.
locals {
  content_dir = coalesce(var.content_dir, "${path.module}/site")

  mime_types = {
    html        = "text/html"
    css         = "text/css"
    js          = "text/javascript"
    mjs         = "text/javascript"
    json        = "application/json"
    map         = "application/json"
    svg         = "image/svg+xml"
    ico         = "image/x-icon"
    png         = "image/png"
    jpg         = "image/jpeg"
    jpeg        = "image/jpeg"
    webp        = "image/webp"
    gif         = "image/gif"
    mp4         = "video/mp4"
    webm        = "video/webm"
    txt         = "text/plain"
    xml         = "application/xml"
    woff        = "font/woff"
    woff2       = "font/woff2"
    ttf         = "font/ttf"
    webmanifest = "application/manifest+json"
  }
}

resource "aws_s3_object" "content" {
  for_each = fileset(local.content_dir, "**")

  bucket       = aws_s3_bucket.site.id
  key          = each.value
  source       = "${local.content_dir}/${each.value}"
  etag         = filemd5("${local.content_dir}/${each.value}")
  content_type = lookup(local.mime_types, lower(regex("[^.]*$", each.value)), "application/octet-stream")
  tags         = var.tags
}

data "aws_caller_identity" "current" {}
