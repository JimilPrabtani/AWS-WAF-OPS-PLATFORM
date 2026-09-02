# ---------------------------------------------------------------------------
# IP sets
#
# Three sets, and the third one is the interesting one.
#
#   blocked       - addresses to reject outright. Auto-remediation writes here
#                   at runtime, so Terraform must not fight it (see lifecycle).
#   trusted       - addresses that specific rules may exempt. NEVER a global
#                   allow: see the mode validation in variables.tf.
#   never_matches - deliberately empty, and stays empty.
#
# `never_matches` exists so the module has ONE code path instead of two.
# Every exemptible rule is written as:
#
#     and_statement {
#       statement { <the actual check> }
#       statement { not_statement { ip_set_reference_statement { <exempt set> } } }
#     }
#
# When a rule opts into exemption, <exempt set> is `trusted`. When it does not,
# <exempt set> is `never_matches` -- an empty set matches nothing, so NOT(nothing)
# is always true and the AND collapses to just the real check. Without this,
# every rule would need its statement written out twice, once wrapped and once
# bare. Cost is roughly 1 WCU per rule, out of a 1500 WCU default budget.
# ---------------------------------------------------------------------------

locals {
  ip_version = "IPV4"
}

resource "aws_wafv2_ip_set" "blocked" {
  name               = "${var.name}-blocked"
  description        = "Denied addresses. Entries may be added at runtime by auto-remediation."
  scope              = var.scope
  ip_address_version = local.ip_version
  addresses          = var.blocked_ip_cidrs
  tags               = var.tags

  lifecycle {
    # Auto-remediation adds addresses to this set outside of Terraform. Without
    # this, the next `apply` would silently unblock everything that was blocked
    # since the last one.
    ignore_changes = [addresses]
  }
}

resource "aws_wafv2_ip_set" "trusted" {
  name               = "${var.name}-trusted"
  description        = "Addresses that individual rules may exempt themselves for. Not a global allow."
  scope              = var.scope
  ip_address_version = local.ip_version
  addresses          = var.trusted_ip_cidrs
  tags               = var.tags
}

resource "aws_wafv2_ip_set" "never_matches" {
  name               = "${var.name}-never-matches"
  description        = "Intentionally empty. Used as a no-op operand so exemptible rules have a single code path."
  scope              = var.scope
  ip_address_version = local.ip_version
  addresses          = []
  tags               = var.tags
}

# ---------------------------------------------------------------------------
# Regex pattern sets
# ---------------------------------------------------------------------------

# Acceptable Origin / Referer values for origin_check rules. A regex set is used
# instead of an OrStatement of byte matches because WAFv2 rejects an OrStatement
# with fewer than two children -- a single allowed origin would break the build.
resource "aws_wafv2_regex_pattern_set" "allowed_origins" {
  count = length(var.allowed_origins) > 0 ? 1 : 0

  name        = "${var.name}-allowed-origins"
  description = "Origins considered first-party for state-changing requests."
  scope       = var.scope
  tags        = var.tags

  dynamic "regular_expression" {
    for_each = var.allowed_origins
    content {
      regex_string = regular_expression.value
    }
  }
}

# One scope-down pattern set per rate_limit rule. When the rule names no URI
# prefixes the pattern is ".*", which matches everything -- again keeping a
# single code path rather than conditionally emitting the scope_down block.
resource "aws_wafv2_regex_pattern_set" "rate_scope" {
  for_each = { for r in var.rules : r.name => r if r.type == "rate_limit" }

  name        = "${var.name}-rate-scope-${lower(replace(each.key, "_", "-"))}"
  description = "URI scope for rate limit rule ${each.key}."
  scope       = var.scope
  tags        = var.tags

  dynamic "regular_expression" {
    for_each = length(each.value.config.scope_down_uri_prefixes) > 0 ? [
      for p in each.value.config.scope_down_uri_prefixes : "^${p}"
    ] : [".*"]
    content {
      regex_string = regular_expression.value
    }
  }
}
