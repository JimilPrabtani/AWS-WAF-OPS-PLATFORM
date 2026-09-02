variable "name" {
  description = "Name prefix for the bucket, distribution and policies."
  type        = string
}

variable "web_acl_arn" {
  description = "ARN of a CLOUDFRONT-scoped Web ACL. Required -- see the lifecycle precondition in cloudfront.tf."
  type        = string
}

variable "cache_policy_name" {
  description = <<-EOT
    AWS managed cache policy to attach.

    Defaults to Managed-CachingDisabled so that every request reaches the origin
    and test results are deterministic. WAF evaluates before the cache either
    way, so blocking is unaffected -- but a cached 200 can mask an origin change
    mid-test. A real site would use Managed-CachingOptimized.
  EOT
  type        = string
  default     = "Managed-CachingDisabled"
}

variable "content_dir" {
  description = <<-EOT
    Directory whose files are uploaded to the origin bucket. Defaults to the
    module's placeholder site/ so the module works standalone; set it to an
    application's build output (e.g. a Vite dist/) to serve a real site.
  EOT
  type        = string
  default     = null
}

variable "spa_fallback" {
  description = <<-EOT
    Map CloudFront 403/404 responses to /index.html with a 200. Required for
    single-page apps with client-side routing: the OAC'd REST origin returns
    403 for keys that do not exist, so deep links break without this.
  EOT
  type        = bool
  default     = false
}

variable "content_security_policy" {
  description = "Content-Security-Policy header value attached to every response."
  type        = string
  default     = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
}

variable "api_origin_domain" {
  description = <<-EOT
    Hostname of an API to serve under /api/* (e.g. an API Gateway invoke
    domain). Null means no API origin. When set, origin_verify_secret must be
    set too -- the distribution injects it as the x-origin-verify header so the
    API can refuse traffic that skipped CloudFront and the WAF.
  EOT
  type        = string
  default     = null
}

variable "origin_verify_secret" {
  description = "Shared secret sent to the API origin as x-origin-verify."
  type        = string
  default     = null
  sensitive   = true
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
