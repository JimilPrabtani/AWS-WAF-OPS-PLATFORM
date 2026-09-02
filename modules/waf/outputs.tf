output "web_acl_arn" {
  description = "ARN of the Web ACL. CloudFront takes this in its web_acl_id argument; ALB associations take it as web_acl_arn."
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "Web ACL id."
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_name" {
  description = "Web ACL name. Also the value of the WebACL dimension on every AWS/WAFV2 CloudWatch metric."
  value       = aws_wafv2_web_acl.this.name
}

output "web_acl_capacity" {
  description = "Consumed WAF Capacity Units. Budget is 1500 WCU by default. Reported in the evidence bundle."
  value       = aws_wafv2_web_acl.this.capacity
}

output "log_group_name" {
  description = "CloudWatch log group receiving WAF request logs. Consumed by the observability module and by `wafops logs query`."
  value       = var.logging.enabled ? aws_cloudwatch_log_group.waf[0].name : null
}

output "log_group_arn" {
  description = "ARN of the WAF log group."
  value       = var.logging.enabled ? aws_cloudwatch_log_group.waf[0].arn : null
}

output "blocked_ip_set" {
  description = "Identifiers of the blocked IP set, so `wafops ipset block` can update it without a config file."
  value = {
    name  = aws_wafv2_ip_set.blocked.name
    id    = aws_wafv2_ip_set.blocked.id
    arn   = aws_wafv2_ip_set.blocked.arn
    scope = var.scope
  }
}

output "trusted_ip_set" {
  description = "Identifiers of the trusted IP set."
  value = {
    name  = aws_wafv2_ip_set.trusted.name
    id    = aws_wafv2_ip_set.trusted.id
    arn   = aws_wafv2_ip_set.trusted.arn
    scope = var.scope
  }
}

output "rule_summary" {
  description = "Flat rule listing (name, priority, type, mode) for the evidence bundle and the README coverage table."
  value = [
    for r in sort([for x in var.rules : format("%03d|%s|%s|%s", x.priority, x.name, x.type, x.mode)]) :
    {
      priority = tonumber(split("|", r)[0])
      name     = split("|", r)[1]
      type     = split("|", r)[2]
      mode     = split("|", r)[3]
    }
  ]
}
