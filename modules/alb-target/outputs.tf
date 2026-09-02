output "alb_arn" {
  description = "ARN of the load balancer. Pass to aws_wafv2_web_acl_association."
  value       = aws_lb.this.arn
}

output "target_url" {
  description = "Public URL the test suites hit. Plain HTTP -- enforcing TLS here would need an ACM certificate and a domain."
  value       = "http://${aws_lb.this.dns_name}"
}

output "dns_name" {
  description = "Load balancer DNS name."
  value       = aws_lb.this.dns_name
}
