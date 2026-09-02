variable "region" {
  description = "Region for the dev environment. REGIONAL-scoped WAF must match the ALB's region."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name prefix. Must start with wafops- to match the deploy policy's S3 scoping."
  type        = string
  default     = "wafops-dev"
}

variable "trusted_ip_cidrs" {
  description = "Your own address, so rate limiting and geo rules do not fight you during testing. Find it with: curl -s https://checkip.amazonaws.com"
  type        = list(string)
  default     = []
}

variable "allowed_origins" {
  description = "Regex patterns for first-party origins, used by the origin_check rule."
  type        = list(string)
  default     = ["^https?://.*\\.elb\\.amazonaws\\.com$"]
}

variable "alarm_email" {
  description = "Address to receive alarm notifications. Null creates the topic with no subscriber."
  type        = string
  default     = null
}
