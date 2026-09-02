# ---------------------------------------------------------------------------
# security: the account-level, ALWAYS-ON baseline.
#
# Drawn from the AWS Security Reference Architecture, scaled to one account:
# CloudTrail (audit log), AWS Config (required by Security Hub's checks),
# Security Hub CSPM, IAM Access Analyzer, GuardDuty, findings routed to email,
# and a hard budget alert. Deliberately NOT part of the deploy-and-destroy
# cycle: posture management that turns off with the app is not posture
# management.
#
# Cost: CloudTrail free (one mgmt trail) + Config ~$1-3/mo at this resource
# count + Security Hub a few $/mo after its 30-day trial + GuardDuty ~$1-5/mo
# after its trial. Access Analyzer, EventBridge and Budgets are free.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# --- Notifications ---------------------------------------------------------

# Its own topic, not the observability module's: that one is destroyed with
# prod, and security findings must keep reaching someone.
resource "aws_sns_topic" "security" {
  name = "${var.name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alarm_email == null ? 0 : 1

  topic_arn = aws_sns_topic.security.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

data "aws_iam_policy_document" "sns_events" {
  statement {
    sid     = "AllowEventBridgePublish"
    effect  = "Allow"
    actions = ["sns:Publish"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sns_topic.security.arn]
  }
}

resource "aws_sns_topic_policy" "security" {
  arn    = aws_sns_topic.security.arn
  policy = data.aws_iam_policy_document.sns_events.json
}

# --- CloudTrail ------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  bucket        = "${var.name}-trail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.trail.arn]
  }

  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  policy     = data.aws_iam_policy_document.trail_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

# One multi-region management-event trail: inside the CloudTrail free tier.
resource "aws_cloudtrail" "main" {
  name                          = "${var.name}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}

# --- AWS Config (prerequisite for Security Hub CSPM checks) ----------------

resource "aws_s3_bucket" "config" {
  bucket        = "${var.name}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid     = "AWSConfigBucketPermissionsCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl", "s3:ListBucket"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.config.arn]
  }

  statement {
    sid     = "AWSConfigBucketDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket     = aws_s3_bucket.config.id
  policy     = data.aws_iam_policy_document.config_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.config]
}

# The service-linked role is AWS-managed; no hand-rolled Config role to audit.
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.id
  depends_on     = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.config]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# --- Security Hub CSPM -----------------------------------------------------

resource "aws_securityhub_account" "main" {
  enable_default_standards = false # subscribe explicitly below
  depends_on               = [aws_config_configuration_recorder_status.main]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# --- IAM Access Analyzer ---------------------------------------------------

# Continuously flags anything externally accessible. This is the automated,
# always-on version of `wafops verify bypass`: the public-bucket
# misconfiguration this platform was built around would appear here within
# minutes of being introduced.
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "${var.name}-external-access"
  type          = "ACCOUNT"
}

# --- GuardDuty -------------------------------------------------------------

resource "aws_guardduty_detector" "main" {
  enable = true
}

# --- Findings -> email -----------------------------------------------------

resource "aws_cloudwatch_event_rule" "securityhub_high" {
  name        = "${var.name}-securityhub-high"
  description = "HIGH/CRITICAL Security Hub findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["HIGH", "CRITICAL"] }
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_high" {
  rule = aws_cloudwatch_event_rule.securityhub_high.name
  arn  = aws_sns_topic.security.arn
}

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "${var.name}-guardduty-high"
  description = "GuardDuty findings with severity >= 7"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 7] }] }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_high" {
  rule = aws_cloudwatch_event_rule.guardduty_high.name
  arn  = aws_sns_topic.security.arn
}

# --- Budget ----------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.alarm_email == null ? [] : [80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.alarm_email]
    }
  }
}
