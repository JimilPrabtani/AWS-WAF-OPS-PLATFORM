# ---------------------------------------------------------------------------
# dev: a REGIONAL Web ACL in front of a fixed-response ALB.
#
# Comes up in ~90 seconds, costs about 4 cents an hour while running, and is
# where all rule development happens. See modules/alb-target/main.tf for why.
# ---------------------------------------------------------------------------

module "waf" {
  source = "../../modules/waf"

  name  = var.name
  scope = "REGIONAL"
  rules = local.rules

  trusted_ip_cidrs = var.trusted_ip_cidrs
  allowed_origins  = var.allowed_origins

  logging = {
    enabled        = true
    retention_days = 3 # dev is short-lived; nothing here needs to survive a week
  }
}

module "target" {
  source = "../../modules/alb-target"

  name = var.name
}

# REGIONAL ACLs attach to their resource with an explicit association.
# CLOUDFRONT ACLs are attached the other way round -- see envs/prod/main.tf.
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = module.target.alb_arn
  web_acl_arn  = module.waf.web_acl_arn
}

module "observability" {
  source = "../../modules/observability"

  name           = var.name
  web_acl_name   = module.waf.web_acl_name
  log_group_name = module.waf.log_group_name

  # REGIONAL ACLs publish the region name in the Region dimension.
  metric_region_dimension = var.region

  alarm_email = var.alarm_email

  # Loose in dev -- the attack suite deliberately generates blocks, and an alarm
  # that fires on every test run is an alarm nobody reads.
  blocked_requests_threshold = 5000

  detections = {
    scanner_sweep = {
      pattern   = "{ $.action = \"BLOCK\" }"
      threshold = 50
      period    = 300
    }
  }
}
