"""wafops - operational tooling for the WAF Ops Platform.

Division of responsibility, and it is worth being able to state it in one
sentence: Terraform owns everything that *is* (buckets, distributions, Web ACLs,
IP sets, alarms). This package owns everything that *happens* (attacks,
legitimate-traffic checks, log analysis, evidence).
"""
