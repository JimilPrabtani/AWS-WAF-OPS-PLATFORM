variable "name" {
  description = "Name prefix for the Web ACL and all owned resources."
  type        = string
}

variable "scope" {
  description = <<-EOT
    WAFv2 scope. "CLOUDFRONT" Web ACLs MUST be created in us-east-1 and attach only
    to CloudFront distributions. "REGIONAL" Web ACLs live in the same region as the
    ALB / API Gateway / AppSync resource they protect.
  EOT
  type        = string

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "scope must be either CLOUDFRONT or REGIONAL."
  }
}

variable "rules" {
  description = <<-EOT
    The rule set, expressed as data rather than code.

    Every rule is { name, priority, type, mode, config }. `type` selects which
    WAFv2 statement is built; `config` carries only the attributes that type uses.
    Rules are evaluated in ascending priority order and the first terminating
    match wins.
  EOT

  type = list(object({
    name     = string
    priority = number

    # ip_block | rate_limit | managed | geo | origin_check | ua_match
    type = string

    # BLOCK or COUNT. ALLOW is deliberately not permitted -- see validation below.
    mode = string

    config = object({
      # --- type = "managed" ---------------------------------------------------
      managed_rule_group_name = optional(string)
      vendor_name             = optional(string, "AWS")
      managed_rule_version    = optional(string)
      # Per-sub-rule tuning: { "SizeRestrictions_BODY" = "COUNT" }
      rule_action_overrides = optional(map(string), {})

      # --- type = "rate_limit" ------------------------------------------------
      limit                 = optional(number, 300)
      evaluation_window_sec = optional(number, 300)
      # Narrow the rule to specific paths instead of the whole site.
      scope_down_uri_prefixes = optional(list(string), [])

      # --- type = "geo" -------------------------------------------------------
      country_codes = optional(list(string), [])

      # --- type = "origin_check" ----------------------------------------------
      methods = optional(list(string), ["POST", "PUT", "DELETE", "PATCH"])

      # --- type = "ua_match" --------------------------------------------------
      search_strings = optional(list(string), [])

      # --- shared -------------------------------------------------------------
      # When true, requests from var.trusted_ip_cidrs are exempted from THIS rule
      # only. This is the safe replacement for a global terminating ALLOW.
      exempt_trusted_ips = optional(bool, false)
    })
  }))

  validation {
    condition     = length(distinct([for r in var.rules : r.priority])) == length(var.rules)
    error_message = "WAF rule priorities must be unique -- duplicate priorities are rejected by the WAFv2 API."
  }

  validation {
    condition     = length(distinct([for r in var.rules : r.name])) == length(var.rules)
    error_message = "WAF rule names must be unique."
  }

  validation {
    condition     = alltrue([for r in var.rules : contains(["BLOCK", "COUNT"], r.mode)])
    error_message = "Rule mode must be BLOCK or COUNT."
  }

  # This is the v1 bypass, encoded as a machine-checked invariant.
  #
  # In WAFv2 a terminating ALLOW ends rule evaluation for that request. The
  # prototype this project replaces put an ALLOW-on-IP-set rule at priority 0,
  # which silently disabled every subsequent rule -- injection, rate limiting,
  # managed rule groups, all of it -- for any address in that set. Trusted
  # addresses are now expressed as a NotStatement scope-down inside the specific
  # rules that should honour them (config.exempt_trusted_ips), never globally.
  validation {
    condition     = alltrue([for r in var.rules : r.mode != "ALLOW"])
    error_message = "Terminating ALLOW rules are not permitted. Use config.exempt_trusted_ips on the individual rules that should skip trusted addresses."
  }

  validation {
    condition = alltrue([
      for r in var.rules :
      contains(["ip_block", "rate_limit", "managed", "geo", "origin_check", "ua_match"], r.type)
    ])
    error_message = "Unknown rule type. Supported: ip_block, rate_limit, managed, geo, origin_check, ua_match."
  }

  validation {
    condition = alltrue([
      for r in var.rules :
      r.type != "managed" || try(length(r.config.managed_rule_group_name), 0) > 0
    ])
    error_message = "Rules of type 'managed' must set config.managed_rule_group_name."
  }

  # WAFv2 rejects an OrStatement containing fewer than two statements.
  validation {
    condition = alltrue([
      for r in var.rules :
      r.type != "ua_match" || length(r.config.search_strings) >= 2
    ])
    error_message = "ua_match rules need at least two search_strings (WAFv2 OrStatement requires >= 2 statements)."
  }

  validation {
    condition = alltrue([
      for r in var.rules :
      r.type != "origin_check" || length(r.config.methods) >= 2
    ])
    error_message = "origin_check rules need at least two methods (WAFv2 OrStatement requires >= 2 statements)."
  }

  # Cross-variable validation (Terraform >= 1.9): an origin_check rule is
  # meaningless without a set of acceptable origins to compare against.
  validation {
    condition = (
      length([for r in var.rules : r if r.type == "origin_check"]) == 0
      || length(var.allowed_origins) > 0
    )
    error_message = "An origin_check rule is present but var.allowed_origins is empty. Supply at least one regex, e.g. [\"^https://example\\\\.com$\"]."
  }

  validation {
    condition = alltrue([
      for r in var.rules :
      r.type != "rate_limit" || contains([60, 120, 300, 600], r.config.evaluation_window_sec)
    ])
    error_message = "rate_limit evaluation_window_sec must be one of 60, 120, 300, 600."
  }
}

variable "trusted_ip_cidrs" {
  description = "Addresses exempted from rules that opt in via config.exempt_trusted_ips. Never a global allow."
  type        = list(string)
  default     = []
}

variable "blocked_ip_cidrs" {
  description = "Statically blocked addresses. Auto-remediation adds entries here at runtime; ignore_changes keeps Terraform from reverting them."
  type        = list(string)
  default     = []
}

variable "allowed_origins" {
  description = "Regex patterns for acceptable Origin/Referer values, used by origin_check rules. Example: [\"^https://example\\\\.com\"]"
  type        = list(string)
  default     = []
}

variable "logging" {
  description = "WAF request logging. Disabled means no request log exists and every downstream detection is guesswork."
  type = object({
    enabled          = optional(bool, true)
    retention_days   = optional(number, 7)
    redacted_headers = optional(list(string), ["authorization", "cookie", "x-api-key"])
  })
  default = {}
}

variable "tags" {
  description = "Tags applied to every resource. The drift-check workflow finds runaway resources by these."
  type        = map(string)
  default     = {}
}
