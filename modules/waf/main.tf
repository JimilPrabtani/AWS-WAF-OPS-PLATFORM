# ---------------------------------------------------------------------------
# The Web ACL.
#
# Rules arrive as data (var.rules) and each rule TYPE gets its own dynamic
# block below. That is deliberate: WAFv2 statements are heterogeneous, so a
# single fully-generic dynamic block would be unreadable. One block per type
# keeps every statement shape static and greppable, while the rule set itself
# stays as data in envs/*/rules.tf.
#
# Evaluation is by ascending priority and the first TERMINATING match wins.
# COUNT is not terminating -- it records the match and evaluation continues.
# ---------------------------------------------------------------------------

locals {
  by_type = {
    ip_block     = { for r in var.rules : r.name => r if r.type == "ip_block" }
    rate_limit   = { for r in var.rules : r.name => r if r.type == "rate_limit" }
    managed      = { for r in var.rules : r.name => r if r.type == "managed" }
    geo          = { for r in var.rules : r.name => r if r.type == "geo" }
    origin_check = { for r in var.rules : r.name => r if r.type == "origin_check" }
    ua_match     = { for r in var.rules : r.name => r if r.type == "ua_match" }
  }

  # Resolves to the trusted set for rules that opt in, and to the permanently
  # empty set for rules that do not. See the comment block in ip-sets.tf.
  exempt_arn = {
    for r in var.rules : r.name => (
      r.config.exempt_trusted_ips
      ? aws_wafv2_ip_set.trusted.arn
      : aws_wafv2_ip_set.never_matches.arn
    )
  }

  blocked_body = jsonencode({
    error   = "blocked"
    message = "Request blocked by WAF security rules."
  })

  rate_limited_body = jsonencode({
    error   = "rate_limited"
    message = "Too many requests. Try again shortly."
  })
}

resource "aws_wafv2_web_acl" "this" {
  name        = var.name
  description = "WAF Ops Platform - ${var.scope} scope"
  scope       = var.scope
  tags        = var.tags

  # Default-allow. A default-deny edge ACL in front of a public website would
  # require an allow rule for every legitimate request shape, which is not the
  # posture this project is modelling.
  default_action {
    allow {}
  }

  # Blocked requests get a JSON body rather than a bare 403. The test suite
  # asserts on this body: a plain 403 could equally come from S3, the ALB, or a
  # missing object, so status code alone cannot prove the WAF acted.
  custom_response_body {
    key          = "blocked"
    content      = local.blocked_body
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "rate_limited"
    content      = local.rate_limited_body
    content_type = "APPLICATION_JSON"
  }

  # -------------------------------------------------------------------------
  # type = "ip_block"
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = local.by_type.ip_block

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.mode == "BLOCK" ? [1] : []
          content {
            custom_response {
              response_code            = 403
              custom_response_body_key = "blocked"
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.mode == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocked.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # type = "rate_limit"
  #
  # A rate-based statement cannot be nested inside And/Or/Not, so the trusted-IP
  # exemption and the URI narrowing both live in its scope_down_statement.
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = local.by_type.rate_limit

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.mode == "BLOCK" ? [1] : []
          content {
            custom_response {
              response_code            = 429
              custom_response_body_key = "rate_limited"
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.mode == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit                 = rule.value.config.limit
          aggregate_key_type    = "IP"
          evaluation_window_sec = rule.value.config.evaluation_window_sec

          scope_down_statement {
            and_statement {
              statement {
                regex_pattern_set_reference_statement {
                  arn = aws_wafv2_regex_pattern_set.rate_scope[rule.key].arn
                  field_to_match {
                    uri_path {}
                  }
                  text_transformation {
                    priority = 0
                    type     = "URL_DECODE"
                  }
                  text_transformation {
                    priority = 1
                    type     = "LOWERCASE"
                  }
                }
              }

              statement {
                not_statement {
                  statement {
                    ip_set_reference_statement {
                      arn = local.exempt_arn[rule.key]
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # type = "managed"
  #
  # Managed groups use override_action, not action:
  #   none  {} -> the group's own per-rule actions apply (i.e. it blocks)
  #   count {} -> every match is counted instead, and nothing is blocked
  #
  # rule_action_overrides is the tuning surface. It replaces the deprecated
  # `excluded_rules` argument and can downgrade a single noisy sub-rule to COUNT
  # without disabling the rest of the group.
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = local.by_type.managed

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = rule.value.mode == "BLOCK" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.mode == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.config.managed_rule_group_name
          vendor_name = rule.value.config.vendor_name
          version     = rule.value.config.managed_rule_version

          dynamic "rule_action_override" {
            for_each = rule.value.config.rule_action_overrides

            content {
              name = rule_action_override.key
              action_to_use {
                dynamic "count" {
                  for_each = rule_action_override.value == "COUNT" ? [1] : []
                  content {}
                }
                dynamic "allow" {
                  for_each = rule_action_override.value == "ALLOW" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value == "BLOCK" ? [1] : []
                  content {}
                }
              }
            }
          }

          dynamic "scope_down_statement" {
            for_each = rule.value.config.exempt_trusted_ips ? [1] : []
            content {
              not_statement {
                statement {
                  ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.trusted.arn
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # type = "geo"
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = local.by_type.geo

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.mode == "BLOCK" ? [1] : []
          content {
            custom_response {
              response_code            = 403
              custom_response_body_key = "blocked"
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.mode == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        and_statement {
          statement {
            geo_match_statement {
              country_codes = rule.value.config.country_codes
            }
          }

          statement {
            not_statement {
              statement {
                ip_set_reference_statement {
                  arn = local.exempt_arn[rule.key]
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # type = "origin_check"
  #
  # Replaces the prototype's "CSRF" rule. That rule blocked mutating requests
  # whose x-csrf-token header was empty -- but WAF has no session state, so the
  # token was never validated and any attacker could send `x-csrf-token: x`.
  #
  # This rule checks something a WAF can actually assert: a state-changing
  # request should carry an Origin from a host we recognise. A request with NO
  # Origin header does not match the regex set, so NOT(match) is true and it is
  # blocked -- which is the intended behaviour.
  #
  # This is defence in depth, not CSRF protection. Real CSRF defence is SameSite
  # cookies plus server-side token validation. See docs/THREAT-MODEL.md.
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = local.by_type.origin_check

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.mode == "BLOCK" ? [1] : []
          content {
            custom_response {
              response_code            = 403
              custom_response_body_key = "blocked"
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.mode == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        and_statement {
          # 1. the request uses a state-changing method
          statement {
            or_statement {
              dynamic "statement" {
                for_each = rule.value.config.methods
                content {
                  byte_match_statement {
                    positional_constraint = "EXACTLY"
                    search_string         = statement.value
                    field_to_match {
                      method {}
                    }
                    text_transformation {
                      priority = 0
                      type     = "UPPERCASE"
                    }
                  }
                }
              }
            }
          }

          # 2. ...and its Origin is not one we recognise
          statement {
            not_statement {
              statement {
                regex_pattern_set_reference_statement {
                  arn = aws_wafv2_regex_pattern_set.allowed_origins[0].arn
                  field_to_match {
                    single_header {
                      name = "origin"
                    }
                  }
                  text_transformation {
                    priority = 0
                    type     = "LOWERCASE"
                  }
                }
              }
            }
          }

          # 3. ...and it is not from a trusted address
          statement {
            not_statement {
              statement {
                ip_set_reference_statement {
                  arn = local.exempt_arn[rule.key]
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # -------------------------------------------------------------------------
  # type = "ua_match"
  #
  # Kept permanently in COUNT. Substring matching on User-Agent is evaded by one
  # curl flag, and blocking on it takes out legitimate automation. It earns its
  # place as a signal feeding the scanner-sweep detection, not as a control.
  # -------------------------------------------------------------------------
  dynamic "rule" {
    for_each = local.by_type.ua_match

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.mode == "BLOCK" ? [1] : []
          content {
            custom_response {
              response_code            = 403
              custom_response_body_key = "blocked"
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.mode == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        and_statement {
          statement {
            or_statement {
              dynamic "statement" {
                for_each = rule.value.config.search_strings
                content {
                  byte_match_statement {
                    positional_constraint = "CONTAINS"
                    search_string         = statement.value
                    field_to_match {
                      single_header {
                        name = "user-agent"
                      }
                    }
                    text_transformation {
                      priority = 0
                      type     = "LOWERCASE"
                    }
                  }
                }
              }
            }
          }

          statement {
            not_statement {
              statement {
                ip_set_reference_statement {
                  arn = local.exempt_arn[rule.key]
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = replace(var.name, "-", "")
    sampled_requests_enabled   = true
  }
}
