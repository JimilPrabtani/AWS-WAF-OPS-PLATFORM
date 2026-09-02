# ---------------------------------------------------------------------------
# The dev rule set.
#
# dev exists to observe, so almost everything runs in COUNT. Nothing here is
# promoted to BLOCK until docs/RULE-TUNING-REPORT.md has data supporting it --
# that promotion is the whole point of having two environments.
#
# Compare against envs/prod/rules.tf: same rules, same priorities, different
# modes and tighter thresholds. That diff IS the environment promotion story.
# ---------------------------------------------------------------------------

locals {
  rules = [
    # -----------------------------------------------------------------------
    # 10 - Addresses we have already decided about.
    # Blocks even in dev: this set is only ever populated deliberately.
    # -----------------------------------------------------------------------
    {
      name     = "BlockedIPs"
      priority = 10
      type     = "ip_block"
      mode     = "BLOCK"
      config   = {}
    },

    # -----------------------------------------------------------------------
    # 20 - Rate limiting.
    #
    # A deliberately loose limit in dev so the attack suite can run without
    # tripping it and masking the results of every later rule.
    #
    # exempt_trusted_ips is how the prototype's priority-0 terminating ALLOW is
    # correctly expressed: your address skips THIS rule, and nothing else.
    # -----------------------------------------------------------------------
    {
      name     = "RateLimit"
      priority = 20
      type     = "rate_limit"
      mode     = "COUNT"
      config = {
        limit                 = 2000
        evaluation_window_sec = 300
        exempt_trusted_ips    = true
      }
    },

    # -----------------------------------------------------------------------
    # 30 - The AWS Common Rule Set: SQLi, XSS, LFI, RFI, bad request shapes.
    #
    # COUNT in both environments until tuned. rule_action_overrides is the
    # tuning surface -- add entries here as the report justifies them, one per
    # noisy sub-rule, rather than disabling the whole group.
    # -----------------------------------------------------------------------
    {
      name     = "AWSCommonRuleSet"
      priority = 30
      type     = "managed"
      mode     = "COUNT"
      config = {
        managed_rule_group_name = "AWSManagedRulesCommonRuleSet"
        vendor_name             = "AWS"
        rule_action_overrides   = {}
      }
    },

    # -----------------------------------------------------------------------
    # 40 - Known Bad Inputs: Log4Shell, SSRF, path traversal, host-header
    # injection. The best value-per-WCU rule group AWS publishes, and low enough
    # false-positive risk to block from day one.
    # -----------------------------------------------------------------------
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

    # -----------------------------------------------------------------------
    # 50 - VPN, Tor and hosting-provider ranges.
    #
    # Stays in COUNT in BOTH environments. Plenty of legitimate users are behind
    # a VPN, so blocking this outright trades real customers for a marginal
    # signal. It is here because it is a useful field in the log.
    # -----------------------------------------------------------------------
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

    # -----------------------------------------------------------------------
    # 60 - Geography.
    #
    # Documented in THREAT-MODEL.md as noise reduction, NOT a security boundary:
    # any VPN defeats it in one click. It is here because it measurably reduces
    # background scanner volume, which is a real operational benefit and a
    # different claim from "this stops attackers".
    # -----------------------------------------------------------------------
    {
      name     = "GeoRestriction"
      priority = 60
      type     = "geo"
      mode     = "COUNT"
      config = {
        country_codes      = ["RU", "CN", "KP", "IR"]
        exempt_trusted_ips = true
      }
    },

    # -----------------------------------------------------------------------
    # 70 - Origin validation on state-changing methods.
    #
    # Replaces the prototype's CSRFProtection rule. See the long comment above
    # this rule type in modules/waf/main.tf for why the original did nothing.
    # -----------------------------------------------------------------------
    {
      name     = "OriginValidation"
      priority = 70
      type     = "origin_check"
      mode     = "COUNT"
      config = {
        methods            = ["POST", "PUT", "DELETE", "PATCH"]
        exempt_trusted_ips = true
      }
    },

    # -----------------------------------------------------------------------
    # 80 - Suspicious user agents.
    #
    # COUNT permanently, in every environment. `curl -A "Mozilla/5.0"` defeats
    # it entirely, and blocking on it takes out health checks, CI and monitoring.
    # It feeds the scanner-sweep detection; it is not a control.
    #
    # Note that the prototype BLOCKED on this list, and the list included
    # python-requests -- the default user agent of its own test suite.
    # -----------------------------------------------------------------------
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
