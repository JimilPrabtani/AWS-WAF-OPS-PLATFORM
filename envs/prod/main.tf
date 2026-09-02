# ---------------------------------------------------------------------------
# prod: a CLOUDFRONT-scoped Web ACL in front of a private S3 origin.
#
# The distribution takes 15-20 minutes to deploy and about the same to tear
# down, which is exactly why rule development happens in dev. This environment
# is for validating a rule set that dev has already proven.
# ---------------------------------------------------------------------------

module "waf" {
  source = "../../modules/waf"

  name  = var.name
  scope = "CLOUDFRONT" # requires the us-east-1 provider above
  rules = local.rules

  trusted_ip_cidrs = var.trusted_ip_cidrs
  allowed_origins  = var.allowed_origins

  logging = {
    enabled        = true
    retention_days = 7
  }
}

# CSP for the wandor SPA. Every third-party origin the app talks to must be
# listed here or the browser blocks it -- keep in sync with wandor/index.html
# and its runtime calls. Notably ABSENT: generativelanguage.googleapis.com
# (AI calls now go through /api, same-origin) and accounts.google.com scripts
# (Google sign-in is a redirect through the Cognito hosted UI, and top-level
# navigation is not CSP-constrained).
locals {
  # connect-src: Cognito SRP auth + hosted-UI token exchange + RUM ingestion.
  wandor_csp = join("; ", [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https://images.unsplash.com https://api.dicebear.com",
    "media-src 'self'",
    "connect-src 'self' https://cognito-idp.us-east-1.amazonaws.com https://*.auth.us-east-1.amazoncognito.com https://cognito-identity.us-east-1.amazonaws.com https://dataplane.rum.us-east-1.amazonaws.com https://sts.us-east-1.amazonaws.com",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
  ])
}

# The application's persistent layer (Cognito, DynamoDB, secret) lives in
# envs/data so `destroy` here never touches user accounts or trips. Apply that
# root before this one. Everything app-backend below is gated on content_dir:
# no app being served means no API to build (and CI plans, which have no
# wandor checkout and no data state, stay green).
data "terraform_remote_state" "data" {
  count = var.content_dir == null ? 0 : 1

  backend = "s3"
  config = {
    bucket = "REPLACE_ME_STATE_BUCKET" # same bucket as backend.tf
    key    = "envs/data/terraform.tfstate"
    region = "us-east-1"
  }
}

# Proof-of-path secret shared by CloudFront and the Lambda; rotates on every
# fresh prod deploy, which is every deploy under deploy-and-destroy.
resource "random_password" "origin_verify" {
  count   = var.content_dir == null ? 0 : 1
  length  = 32
  special = false
}

module "api" {
  count  = var.content_dir == null ? 0 : 1
  source = "../../modules/api"

  name                 = var.name
  table_name           = data.terraform_remote_state.data[0].outputs.table_name
  table_arn            = data.terraform_remote_state.data[0].outputs.table_arn
  ai_keys_secret_arn   = data.terraform_remote_state.data[0].outputs.ai_keys_secret_arn
  user_pool_id         = data.terraform_remote_state.data[0].outputs.user_pool_id
  user_pool_client_id  = data.terraform_remote_state.data[0].outputs.user_pool_client_id
  origin_verify_secret = random_password.origin_verify[0].result
}

module "site" {
  source = "../../modules/static-site"

  name = var.name

  # A CLOUDFRONT ACL is attached by the distribution referencing it, not by a
  # separate association resource. The module has a lifecycle precondition that
  # refuses to build a distribution without one -- an unprotected origin is the
  # exact defect this project exists to fix.
  web_acl_arn = module.waf.web_acl_arn

  content_dir             = var.content_dir
  spa_fallback            = var.content_dir != null # placeholder page needs no fallback
  content_security_policy = local.wandor_csp

  api_origin_domain    = var.content_dir == null ? null : module.api[0].api_origin_domain
  origin_verify_secret = var.content_dir == null ? null : random_password.origin_verify[0].result
}

module "observability" {
  source = "../../modules/observability"

  name           = var.name
  web_acl_name   = module.waf.web_acl_name
  log_group_name = module.waf.log_group_name

  # CLOUDFRONT-scoped ACLs publish "CloudFront" in the Region dimension rather
  # than a region name. Getting this wrong produces a dashboard of empty graphs
  # while the WAF is visibly counting requests.
  metric_region_dimension = "CloudFront"

  alarm_email                = var.alarm_email
  blocked_requests_threshold = 100

  api = var.content_dir == null ? null : {
    lambda_function_name  = module.api[0].lambda_function_name
    api_id                = module.api[0].api_id
    lambda_log_group_name = module.api[0].lambda_log_group_name
    table_name            = data.terraform_remote_state.data[0].outputs.table_name
  }

  detections = {
    scanner_sweep = {
      pattern   = "{ $.action = \"BLOCK\" }"
      threshold = 50
      period    = 300
    }
  }
}
