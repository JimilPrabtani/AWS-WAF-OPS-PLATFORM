variable "name" {
  description = "Name prefix for dashboards, alarms and the notification topic."
  type        = string
}

variable "web_acl_name" {
  description = "Web ACL name. This is the value of the WebACL dimension on AWS/WAFV2 metrics."
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch log group receiving WAF request logs. Metric filters are attached here."
  type        = string
}

variable "metric_region_dimension" {
  description = <<-EOT
    Value of the `Region` dimension on AWS/WAFV2 metrics.

    REGIONAL-scoped ACLs publish the region name (e.g. "us-east-1").
    CLOUDFRONT-scoped ACLs publish "CloudFront".

    Worth confirming in the console on your first deploy -- if the dashboard
    renders empty graphs while the WAF is clearly counting requests, this
    dimension is the reason.
  EOT
  type        = string
}

variable "alarm_email" {
  description = <<-EOT
    Address to subscribe to the notification topic. Leave null to create the
    topic without a subscriber.

    AWS sends a confirmation email; the subscription stays "pending" until you
    click it, and Terraform cannot confirm it for you.
  EOT
  type        = string
  default     = null
}

variable "blocked_requests_threshold" {
  description = "Blocked requests in a 5-minute window that should raise an alarm."
  type        = number
  default     = 100
}

variable "detections" {
  description = <<-EOT
    Metric filters generated from detections/*.yaml. Each entry turns matching
    log records into a CloudWatch metric so a detection can raise an alarm
    rather than only being queryable after the fact.
  EOT
  type = map(object({
    pattern   = string
    threshold = number
    period    = optional(number, 300)
  }))
  default = {}
}

variable "api" {
  description = <<-EOT
    Application API to monitor alongside the WAF. Null means WAF-only (dev, or
    prod serving the placeholder). When set, adds alarms for Lambda errors,
    API Gateway 5xx, DynamoDB throttles and repeated AI-provider failovers,
    plus an API row on the dashboard.
  EOT
  type = object({
    lambda_function_name  = string
    api_id                = string
    lambda_log_group_name = string
    table_name            = string
  })
  default = null
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
