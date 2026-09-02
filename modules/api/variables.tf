variable "name" {
  description = "Name prefix for the Lambda, API and IAM role."
  type        = string
}

variable "table_name" {
  description = "DynamoDB table holding trips and the per-user counter."
  type        = string
}

variable "table_arn" {
  description = "ARN of the trips table, for the IAM policy."
  type        = string
}

variable "ai_keys_secret_arn" {
  description = "Secrets Manager secret with the Gemini/OpenRouter keys."
  type        = string
}

variable "user_pool_id" {
  description = "Cognito user pool whose JWTs the authorizer accepts."
  type        = string
}

variable "user_pool_client_id" {
  description = "App client id used as the JWT audience."
  type        = string
}

variable "origin_verify_secret" {
  description = "Shared secret CloudFront injects as x-origin-verify; the Lambda rejects requests without it."
  type        = string
  sensitive   = true
}

variable "gemini_model" {
  description = "Primary model id (pinned deliberately -- OWASP LLM03)."
  type        = string
  default     = "gemini-3.6-flash"
}

variable "openrouter_model" {
  description = "Failover model id on OpenRouter."
  type        = string
  default     = "openai/gpt-4o-mini"
}

variable "trip_limit" {
  description = "Lifetime free-plan generation cap per user."
  type        = number
  default     = 7
}

variable "log_retention_days" {
  type    = number
  default = 7
}

variable "tags" {
  type    = map(string)
  default = {}
}
