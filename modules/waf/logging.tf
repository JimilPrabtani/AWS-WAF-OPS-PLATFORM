# ---------------------------------------------------------------------------
# Request logging.
#
# The prototype never called PutLoggingConfiguration, so no request log existed.
# Its "threat detection" ran on GetSampledRequests -- a bounded sample from a
# short trailing window, not a log -- which makes every count derived from it
# unreliable. This is the fix, and everything in detections/ depends on it.
#
# CloudWatch Logs rather than Kinesis Firehose -> S3 -> Athena. Firehose is the
# right architecture at scale but it bills continuously, which does not fit a
# deploy-and-destroy posture. Logs Insights gives the same demonstration value
# for cents. See docs/COST-MODEL.md.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "waf" {
  count = var.logging.enabled ? 1 : 0

  # The "aws-waf-logs-" prefix is MANDATORY. WAF refuses any other log group
  # name, and the API error does not tell you why.
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = var.logging.retention_days
  tags              = var.tags
}

# Lets the log-delivery service write into the group above. Depending on account
# history AWS sometimes provisions this itself; creating it explicitly makes the
# deployment reproducible in a fresh account. The SourceAccount condition is a
# confused-deputy guard: without it the policy trusts the delivery service on
# behalf of any account, not just yours.
data "aws_iam_policy_document" "waf_logs" {
  count = var.logging.enabled ? 1 : 0

  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.waf[0].arn}:*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  count = var.logging.enabled ? 1 : 0

  policy_name     = "${var.name}-waf-logs"
  policy_document = data.aws_iam_policy_document.waf_logs[0].json
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = var.logging.enabled ? 1 : 0

  resource_arn = aws_wafv2_web_acl.this.arn

  # The log group ARN here must NOT carry a trailing ":*". The
  # aws_cloudwatch_log_group.arn attribute is already in the correct form.
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  # Redaction happens before the record is written, so these headers never land
  # in the log in plaintext.
  dynamic "redacted_fields" {
    for_each = var.logging.redacted_headers
    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }

  # The delivery permission must exist before WAF is told to deliver, otherwise
  # the first apply in a fresh account fails with an opaque error.
  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
