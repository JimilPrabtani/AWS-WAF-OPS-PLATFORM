variable "region" {
  description = "Kept in us-east-1 alongside prod; the data here is region-bound."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name prefix for the application's persistent resources."
  type        = string
  default     = "wandor"
}

variable "callback_urls" {
  description = <<-EOT
    OAuth callback URLs for the SPA app client. Each prod deploy mints a new
    CloudFront domain, so after `apply` in envs/prod add
    "https://<new-domain>/login" here and re-apply this root (an in-place
    client update, seconds). localhost stays for local dev.
  EOT
  type        = list(string)
  default     = ["http://localhost:5173/login"]
}

variable "logout_urls" {
  description = "OAuth sign-out redirect URLs. Same churn rule as callback_urls."
  type        = list(string)
  default     = ["http://localhost:5173/"]
}

variable "google_client_id" {
  description = "Google OAuth client id for federated sign-in. Null disables the Google IdP."
  type        = string
  default     = null
}

variable "google_client_secret" {
  description = "Google OAuth client secret. Set in terraform.tfvars (gitignored)."
  type        = string
  default     = null
  sensitive   = true
}

variable "tags" {
  description = "Extra tags."
  type        = map(string)
  default     = {}
}
