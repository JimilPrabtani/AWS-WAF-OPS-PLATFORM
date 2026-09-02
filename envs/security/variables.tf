variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  description = "Name prefix. Must start with wafops- to match the deploy policy's S3 scoping."
  type        = string
  default     = "wafops-security"
}

variable "alarm_email" {
  description = "Address for security findings and the budget alert. Null skips the subscriptions."
  type        = string
  default     = null
}

variable "monthly_budget_usd" {
  description = "Account-wide monthly cost ceiling that triggers an alert."
  type        = number
  default     = 5
}
