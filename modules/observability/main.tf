# ---------------------------------------------------------------------------
# Alerting, dashboard, and detection metric filters.
#
# The prototype created two CloudWatch alarms with ActionsEnabled = false and
# no SNS topic, so they could never notify anyone -- an alarm that cannot fire
# an action is a graph, not an alarm. Everything here is wired end to end.
# ---------------------------------------------------------------------------

locals {
  common_dimensions = {
    WebACL = var.web_acl_name
    Region = var.metric_region_dimension
  }

  metric_namespace = "WAFOps/${var.name}"
}

resource "aws_sns_topic" "alerts" {
  name = "${var.name}-waf-alerts"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alarm_email == null ? 0 : 1

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---------------------------------------------------------------------------
# Alarms on AWS/WAFV2 metrics
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "blocked_spike" {
  alarm_name          = "${var.name}-waf-blocked-spike"
  alarm_description   = "WAF blocked more than ${var.blocked_requests_threshold} requests in 5 minutes. Expected during a test run; investigate otherwise."
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.blocked_requests_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = merge(local.common_dimensions, { Rule = "ALL" })

  actions_enabled = true
  alarm_actions   = [aws_sns_topic.alerts.arn]
  ok_actions      = [aws_sns_topic.alerts.arn]

  tags = var.tags
}

# A sustained drop in ALLOWED traffic while blocks climb is the shape of a
# false-positive incident: the rules are working "correctly" and taking the site
# down. This is the alarm the prototype had no equivalent of.
resource "aws_cloudwatch_metric_alarm" "allowed_collapse" {
  alarm_name          = "${var.name}-waf-allowed-collapse"
  alarm_description   = "Allowed request volume collapsed. Usually means a rule change is blocking legitimate traffic."
  namespace           = "AWS/WAFV2"
  metric_name         = "AllowedRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = merge(local.common_dimensions, { Rule = "ALL" })

  actions_enabled = true
  alarm_actions   = [aws_sns_topic.alerts.arn]

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Detection metric filters
#
# detections/*.yaml holds each detection's query, threshold and rationale; the
# alertable subset is wired here by hand via the `detections` map in
# envs/*/main.tf (see detections/README.md, step 6).
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = var.detections

  name           = "${var.name}-${each.key}"
  log_group_name = var.log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = local.metric_namespace
    value     = "1"
    unit      = "Count"

    # Without this, periods with no matches report as missing data rather than
    # zero, and the alarm sits in INSUFFICIENT_DATA instead of OK.
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = var.detections

  alarm_name          = "${var.name}-detect-${each.key}"
  alarm_description   = "Detection '${each.key}' exceeded its tuned threshold. Rationale: see detections/${each.key}.yaml"
  namespace           = local.metric_namespace
  metric_name         = each.key
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  actions_enabled = true
  alarm_actions   = [aws_sns_topic.alerts.arn]

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Application API alarms (only when an API is deployed)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count = var.api == null ? 0 : 1

  alarm_name          = "${var.name}-api-lambda-errors"
  alarm_description   = "The API Lambda raised errors. Check its log group."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = { FunctionName = var.api.lambda_function_name }

  actions_enabled = true
  alarm_actions   = [aws_sns_topic.alerts.arn]
  tags            = var.tags
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  count = var.api == null ? 0 : 1

  alarm_name          = "${var.name}-api-5xx"
  alarm_description   = "The HTTP API returned 5xx responses."
  namespace           = "AWS/ApiGateway"
  metric_name         = "5xx"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = { ApiId = var.api.api_id }

  actions_enabled = true
  alarm_actions   = [aws_sns_topic.alerts.arn]
  tags            = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ddb_throttles" {
  count = var.api == null ? 0 : 1

  alarm_name          = "${var.name}-api-ddb-throttles"
  alarm_description   = "DynamoDB throttled requests on the trips table."
  namespace           = "AWS/DynamoDB"
  metric_name         = "ThrottledRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = { TableName = var.api.table_name }

  actions_enabled = true
  alarm_actions   = [aws_sns_topic.alerts.arn]
  tags            = var.tags
}

# The Lambda logs "FAILOVER openrouter reason=..." each time Gemini fails and
# OpenRouter takes over. Occasional is fine; repeated means the primary
# provider (or its key) is broken and someone should look.
resource "aws_cloudwatch_log_metric_filter" "ai_failover" {
  count = var.api == null ? 0 : 1

  name           = "${var.name}-ai-failover"
  log_group_name = var.api.lambda_log_group_name
  pattern        = "FAILOVER"

  metric_transformation {
    name          = "AiFailover"
    namespace     = local.metric_namespace
    value         = "1"
    unit          = "Count"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "ai_failover" {
  count = var.api == null ? 0 : 1

  alarm_name          = "${var.name}-ai-failover"
  alarm_description   = "Gemini keeps failing over to OpenRouter. Check the Gemini key/quota."
  namespace           = local.metric_namespace
  metric_name         = "AiFailover"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  actions_enabled = true
  alarm_actions   = [aws_sns_topic.alerts.arn]
  tags            = var.tags
}

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

locals {
  dashboard_region = var.metric_region_dimension == "CloudFront" ? "us-east-1" : var.metric_region_dimension

  # The for-expression over a 0/1-element list sidesteps Terraform's
  # inconsistent-conditional-types error for tuples of different lengths.
  api_widgets = flatten([for api in(var.api == null ? [] : [var.api]) : [
    {
      type   = "metric"
      x      = 0
      y      = 14
      width  = 12
      height = 6
      properties = {
        title  = "API: requests and 5xx"
        view   = "timeSeries"
        region = local.dashboard_region
        stat   = "Sum"
        period = 300
        metrics = [
          ["AWS/ApiGateway", "Count", "ApiId", api.api_id],
          [".", "5xx", ".", "."],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 14
      width  = 12
      height = 6
      properties = {
        title  = "API: Lambda errors, duration, AI failovers"
        view   = "timeSeries"
        region = local.dashboard_region
        period = 300
        metrics = [
          ["AWS/Lambda", "Errors", "FunctionName", api.lambda_function_name, { stat = "Sum" }],
          [".", "Duration", ".", ".", { stat = "Average" }],
          [local.metric_namespace, "AiFailover", { stat = "Sum" }],
        ]
      }
    },
  ]])
}

resource "aws_cloudwatch_dashboard" "waf" {
  dashboard_name = "${var.name}-waf"

  dashboard_body = jsonencode({
    widgets = concat([
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Allowed vs blocked"
          view   = "timeSeries"
          region = var.metric_region_dimension == "CloudFront" ? "us-east-1" : var.metric_region_dimension
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", var.web_acl_name, "Region", var.metric_region_dimension, "Rule", "ALL"],
            [".", "BlockedRequests", ".", ".", ".", ".", ".", "."],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Counted matches (rules not yet promoted to BLOCK)"
          view   = "timeSeries"
          region = var.metric_region_dimension == "CloudFront" ? "us-east-1" : var.metric_region_dimension
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/WAFV2", "CountedRequests", "WebACL", var.web_acl_name, "Region", var.metric_region_dimension, "Rule", "ALL"],
          ]
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 8
        properties = {
          title  = "Top blocked source addresses (last 3h)"
          region = var.metric_region_dimension == "CloudFront" ? "us-east-1" : var.metric_region_dimension
          view   = "table"
          query  = <<-EOQ
            SOURCE '${var.log_group_name}'
            | fields httpRequest.clientIp as ip, terminatingRuleId as rule
            | filter action = "BLOCK"
            | stats count(*) as hits by ip, rule
            | sort hits desc
            | limit 20
          EOQ
        }
      },
    ], local.api_widgets)
  })
}
