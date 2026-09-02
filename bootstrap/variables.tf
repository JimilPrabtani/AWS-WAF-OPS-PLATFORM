variable "region" {
  description = "Region for the state bucket. Keep this stable -- moving it later means migrating state."
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Globally unique name for the Terraform state bucket."
  type        = string
}

variable "github_repository" {
  description = "GitHub repo allowed to assume the CI roles, as \"owner/name\". This is the whole security boundary for CI -- get it exactly right."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in the form owner/name."
  }
}

variable "human_principal_arns" {
  description = "IAM user/role ARNs permitted to assume the local deploy role. Usually just your own IAM user."
  type        = list(string)
  default     = []
}

variable "require_mfa" {
  description = "Require MFA on the human deploy role. Turn this off only if your IAM user has no MFA device yet."
  type        = bool
  default     = true
}
