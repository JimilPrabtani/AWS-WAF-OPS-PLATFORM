# Native Terraform tests (terraform test / tofu test).
#
# These assert the module's CONTRACT -- the invariants that must hold before a
# plan is ever produced. They need `terraform init` for the provider but never
# create real infrastructure, because every run block uses `command = plan`.
#
# Run with:  terraform test -verbose

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

variables {
  name  = "wafops-test"
  scope = "REGIONAL"

  allowed_origins = ["^https://example\\.com$"]

  rules = [
    {
      name     = "BlockedIPs"
      priority = 10
      type     = "ip_block"
      mode     = "BLOCK"
      config   = {}
    },
    {
      name     = "RateLimit"
      priority = 20
      type     = "rate_limit"
      mode     = "COUNT"
      config = {
        limit              = 500
        exempt_trusted_ips = true
      }
    },
  ]
}

run "builds_the_expected_rule_count" {
  command = plan

  assert {
    condition     = length(aws_wafv2_web_acl.this.rule) == 2
    error_message = "Every rule in var.rules must appear in the Web ACL."
  }
}

run "logging_is_on_by_default" {
  command = plan

  assert {
    condition     = length(aws_cloudwatch_log_group.waf) == 1
    error_message = "Logging must default to enabled. Without a request log every detection is guesswork."
  }
}

run "log_group_carries_the_required_prefix" {
  command = plan

  assert {
    condition     = startswith(aws_cloudwatch_log_group.waf[0].name, "aws-waf-logs-")
    error_message = "WAF refuses to deliver to a log group whose name lacks the aws-waf-logs- prefix."
  }
}

run "never_matches_set_stays_empty" {
  command = plan

  assert {
    condition     = length(aws_wafv2_ip_set.never_matches.addresses) == 0
    error_message = "The no-op exemption set must stay empty, or every rule referencing it silently stops matching."
  }
}

# --- the invariants that encode the prototype's bugs ------------------------

run "rejects_terminating_allow" {
  command = plan

  variables {
    rules = [
      {
        name     = "WhitelistTrustedIPs"
        priority = 0
        type     = "ip_block"
        mode     = "ALLOW"
        config   = {}
      },
    ]
  }

  expect_failures = [var.rules]
}

run "rejects_duplicate_priorities" {
  command = plan

  variables {
    rules = [
      {
        name     = "A"
        priority = 10
        type     = "ip_block"
        mode     = "BLOCK"
        config   = {}
      },
      {
        name     = "B"
        priority = 10
        type     = "ip_block"
        mode     = "BLOCK"
        config   = {}
      },
    ]
  }

  expect_failures = [var.rules]
}

run "rejects_origin_check_without_allowed_origins" {
  command = plan

  variables {
    allowed_origins = []
    rules = [
      {
        name     = "OriginValidation"
        priority = 70
        type     = "origin_check"
        mode     = "BLOCK"
        config   = {}
      },
    ]
  }

  expect_failures = [var.rules]
}

run "rejects_single_statement_or" {
  command = plan

  variables {
    rules = [
      {
        name     = "SuspiciousUserAgents"
        priority = 80
        type     = "ua_match"
        mode     = "COUNT"
        config = {
          search_strings = ["sqlmap"]
        }
      },
    ]
  }

  expect_failures = [var.rules]
}
