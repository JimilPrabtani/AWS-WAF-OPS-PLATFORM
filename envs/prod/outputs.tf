output "target_url" {
  description = "The only supported way in. Everything else should 403."
  value       = module.site.target_url
}

output "origin_bypass_url" {
  description = <<-EOT
    The direct S3 REST URL, exposed on purpose. `wafops verify bypass` requests
    it and asserts 403. In the prototype this URL served the site, which meant
    the WAF could be skipped entirely -- proving it now fails is the single most
    important assertion in this repository.
  EOT
  value       = module.site.origin_bypass_url
}

output "distribution_id" {
  value = module.site.distribution_id
}

output "bucket_name" {
  value = module.site.bucket_name
}

output "web_acl_name" {
  value = module.waf.web_acl_name
}

output "web_acl_arn" {
  value = module.waf.web_acl_arn
}

output "web_acl_capacity" {
  description = "Consumed WCU out of the 1500 default budget."
  value       = module.waf.web_acl_capacity
}

output "log_group_name" {
  value = module.waf.log_group_name
}

output "blocked_ip_set" {
  value = module.waf.blocked_ip_set
}

output "rule_summary" {
  value = module.waf.rule_summary
}

output "api_endpoint" {
  description = "Direct HTTP API URL. Requests here without x-origin-verify are refused -- use target_url/api instead."
  value       = var.content_dir == null ? null : module.api[0].api_endpoint
}

output "callback_url_for_data_env" {
  description = "Add this to callback_urls in envs/data/terraform.tfvars after apply, then re-apply that root."
  value       = var.content_dir == null ? null : "${module.site.target_url}/login"
}

output "sns_topic_arn" {
  value = module.observability.sns_topic_arn
}

output "dashboard_name" {
  value = module.observability.dashboard_name
}
