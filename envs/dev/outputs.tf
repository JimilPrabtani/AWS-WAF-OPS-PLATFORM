# These outputs are the contract between the infrastructure and the tooling.
# `wafops` reads them via `terraform output -json` instead of the local JSON
# state file the prototype used, which meant no second machine or CI runner
# could ever run the tests.

output "target_url" {
  description = "What the test suites hit."
  value       = module.target.target_url
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
  description = "Feeds the README coverage table and the evidence bundle."
  value       = module.waf.rule_summary
}

output "sns_topic_arn" {
  value = module.observability.sns_topic_arn
}

output "dashboard_name" {
  value = module.observability.dashboard_name
}

# Present in prod only. Declared here as null so the tooling can read the same
# output name in both environments.
output "origin_bypass_url" {
  description = "Not applicable to dev -- the ALB has no separate origin to bypass."
  value       = null
}
