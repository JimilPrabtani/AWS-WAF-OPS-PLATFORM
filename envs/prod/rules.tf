# ---------------------------------------------------------------------------
# The prod rule set.
#
# Same rules and same priorities as envs/dev/rules.tf. What differs is MODE and
# thresholds -- that diff is the environment-promotion story, and it is meant to
# be read side by side:
#
#     diff envs/dev/rules.tf envs/prod/rules.tf
#
# Nothing is promoted from COUNT to BLOCK here without a corresponding entry in
# docs/RULE-TUNING-REPORT.md. Two rules are still COUNT on purpose, and the
# README's coverage table says so.
# ---------------------------------------------------------------------------

locals {
  rules = [
    {
      name     = "BlockedIPs"
      priority = 10
      type     = "ip_block"
      mode     = "BLOCK"
      config   = {}
    },

    # Tight in prod: 300 requests per 5 minutes per source address, scoped to the
    # paths worth protecting rather than to everything. A static page is cheap to
    # serve; an API route is not.
    {
      name     = "RateLimit"
      priority = 20
      type     = "rate_limit"
      mode     = "BLOCK"
      config = {
        limit                   = 300
        evaluation_window_sec   = 300
        scope_down_uri_prefixes = ["/api/", "/login", "/search"]
        exempt_trusted_ips      = true
      }
    },

    # ---------------------------------------------------------------------
    # STILL IN COUNT, DELIBERATELY.
    #
    # Promoting the Common Rule Set to BLOCK without tuning data is how you take
    # a site down with a rule that is "working correctly". The procedure is in
    # docs/RULE-TUNING-REPORT.md: run COUNT, generate mixed traffic, group the
    # logs by sub-rule, add a rule_action_overrides entry for each sub-rule that
    # fires on legitimate requests, THEN flip mode to BLOCK.
    #
    # Until that report has data in it, the README claims COUNT and not coverage.
    # ---------------------------------------------------------------------
    {
      name     = "AWSCommonRuleSet"
      priority = 30
      type     = "managed"
      mode     = "COUNT"
      config = {
        managed_rule_group_name = "AWSManagedRulesCommonRuleSet"
        vendor_name             = "AWS"

        # Populate from the tuning report, e.g.:
        #   rule_action_overrides = { SizeRestrictions_BODY = "COUNT" }
        rule_action_overrides = {}
      }
    },

    {
      name     = "AWSKnownBadInputs"
      priority = 40
      type     = "managed"
      mode     = "BLOCK"
      config = {
        managed_rule_group_name = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name             = "AWS"
      }
    },

    # COUNT in prod too. Blocking every VPN user is a real cost for a marginal
    # signal; this is a logging field, not a control.
    {
      name     = "AWSAnonymousIpList"
      priority = 50
      type     = "managed"
      mode     = "COUNT"
      config = {
        managed_rule_group_name = "AWSManagedRulesAnonymousIpList"
        vendor_name             = "AWS"
      }
    },

    {
      name     = "GeoRestriction"
      priority = 60
      type     = "geo"
      mode     = "BLOCK"
      config = {
        country_codes      = ["RU", "CN", "KP", "IR"]
        exempt_trusted_ips = true
      }
    },

    {
      name     = "OriginValidation"
      priority = 70
      type     = "origin_check"
      mode     = "BLOCK"
      config = {
        methods            = ["POST", "PUT", "DELETE", "PATCH"]
        exempt_trusted_ips = true
      }
    },

    # COUNT permanently. See the note in envs/dev/rules.tf.
    {
      name     = "SuspiciousUserAgents"
      priority = 80
      type     = "ua_match"
      mode     = "COUNT"
      config = {
        search_strings = [
          "sqlmap", "nikto", "nmap", "masscan", "zgrab",
          "gobuster", "dirbuster", "wpscan", "nuclei", "feroxbuster",
        ]
      }
    },
  ]
}
