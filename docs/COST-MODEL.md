# Cost model

Verified against AWS pricing pages for us-east-1. Re-check before publishing;
prices change.

## Rates

| Component | Rate | Source |
|---|---|---|
| WAF Web ACL | $5.00 / month, **prorated hourly** | [AWS WAF pricing](https://aws.amazon.com/waf/pricing) |
| WAF rule | $1.00 / month each, prorated hourly | same |
| WAF managed rule group | $1.00 / month each, prorated hourly | same |
| WAF requests | $0.60 per million | same |
| ALB | $0.0225 / hour + $0.008 / LCU-hour | [ELB pricing](https://aws.amazon.com/elasticloadbalancing/pricing/) |
| CloudFront | Within the perpetual free tier at this volume | — |
| CloudWatch Logs | Ingest + short retention | pennies per run |
| S3 (state + origin) | A few MB | ~$0.01 / month |

Hourly proration is the fact that makes this whole posture work. A Web ACL you
run for two hours costs two hours, not a month.

## Derived figures

**dev, while running**

```
ALB                        $0.02250 / hr
LCU (test volume)        ~ $0.00100 / hr
Web ACL   $5 / 730 hr      $0.00685 / hr
8 rules   $8 / 730 hr      $0.01096 / hr
                          ─────────────
                          ~$0.0413 / hr
```

An eight-hour working session: **about $0.33**.
A full test run is roughly 500 requests → $0.0003. Not material.

**prod, while running**

```
Web ACL   $5 / 730 hr      $0.00685 / hr
8 rules   $8 / 730 hr      $0.01096 / hr
CloudFront                 $0 (free tier)
S3                       ~ $0
                          ─────────────
                          ~$0.0178 / hr
```

Plus roughly 40 minutes of unavoidable CloudFront deploy and teardown time per
cycle. A three-hour validation window: **about $0.06**.

**At rest, everything destroyed:** the state bucket and its versions, roughly
**$0.01 / month**.

**A complete end-to-end validation cycle: under $1.**

## Enforcement, not aspiration

`.github/workflows/drift.yml` runs daily, enumerates WAF Web ACLs, load balancers
and CloudFront distributions belonging to this project, and **fails** if any
exist. The budget posture is a checked control rather than a claim.

## WAF capacity units

Run `terraform output web_acl_capacity` after an apply. WCU is a separate budget
from cost — 1500 by default per Web ACL — and it is what limits how many rules
you can run, not money. Two notes on this configuration:

- The `never_matches` exemption pattern (see the code walkthrough) costs about
  1 WCU per rule. Cheap for the readability it buys.
- Managed rule groups have fixed published capacities; `AWSManagedRulesCommonRuleSet`
  is the largest item here by a wide margin.

Very few candidates think about WCU at all. Reporting it is worth the two minutes.

## What was deliberately not built, and why

| Considered | Cost | Decision |
|---|---|---|
| Firehose → S3 → Athena log pipeline | Always-on Firehose + storage | Rejected. CloudWatch Logs Insights gives ~90% of the demonstration value for cents |
| GuardDuty | Bills continuously | Rejected for a deploy-and-destroy project |
| Security Hub | Needs time to populate | Rejected — nothing to show in a 3-hour window |
| AWS Bot Control | $10 / Web ACL / month + per request | Rejected. Discussed in the threat model as the paid upgrade path |
| Shield Advanced | $3,000 / month | Rejected, obviously. Named so the DDoS gap is explicit |
| Route 53 + ACM custom domain | ~$0.50 / month hosted zone | Open decision. It is what would make HSTS and TLS 1.2 enforcement real |
