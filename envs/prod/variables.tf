variable "region" {
  description = <<-EOT
    Must be us-east-1. A CLOUDFRONT-scoped Web ACL can only be created there,
    and CloudFront's own control plane is global via us-east-1. This is a
    variable rather than a constant purely so the value is visible in the plan.
  EOT
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.region == "us-east-1"
    error_message = "CLOUDFRONT-scoped WAF resources must be created in us-east-1."
  }
}

variable "name" {
  description = "Name prefix. Must start with wafops- to match the deploy policy's S3 scoping."
  type        = string
  default     = "wafops-prod"
}

variable "trusted_ip_cidrs" {
  description = "Addresses exempted by rules that opt in. Keep this list very short in prod."
  type        = list(string)
  default     = []
}

variable "allowed_origins" {
  description = "Regex patterns for first-party origins used by the origin_check rule."
  type        = list(string)
  default     = ["^https://.*\\.cloudfront\\.net$"]
}

variable "content_dir" {
  description = <<-EOT
    Application build output uploaded to the origin bucket, relative to this
    directory. Null serves the module's placeholder page instead -- which is
    also what keeps CI plans working, since the wandor checkout is not present
    there. Set in terraform.tfvars for real deploys:
      content_dir = "../../../wandor/dist"   (run `npm run build` in wandor first)
  EOT
  type        = string
  default     = null
}

variable "alarm_email" {
  description = "Address to receive alarm notifications."
  type        = string
  default     = null
}
