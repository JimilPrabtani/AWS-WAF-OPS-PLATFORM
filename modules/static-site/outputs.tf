output "distribution_id" {
  description = "CloudFront distribution id."
  value       = aws_cloudfront_distribution.site.id
}

output "distribution_arn" {
  description = "CloudFront distribution ARN."
  value       = aws_cloudfront_distribution.site.arn
}

output "target_url" {
  description = "Public URL the test suites hit. This is the ONLY way in."
  value       = "https://${aws_cloudfront_distribution.site.domain_name}"
}

output "bucket_name" {
  description = "Private origin bucket name."
  value       = aws_s3_bucket.site.id
}

output "origin_bypass_url" {
  description = <<-EOT
    The direct S3 REST URL. Exposed as an output ON PURPOSE: `wafops verify bypass`
    requests it and asserts a 403. In the prototype this URL returned the site,
    which meant the WAF could be skipped entirely. Proving it now fails is the
    single most important test in this repository.
  EOT
  value       = "https://${aws_s3_bucket.site.bucket_regional_domain_name}/index.html"
}
