# Rule tuning report

> **Status: not yet populated.** The procedure below has not been run. Nothing in
> this repository claims enforcement that this document does not support, which
> is why `AWSCommonRuleSet` is still `COUNT` in both environments.
>
> Leaving this honest is deliberate. "Two rules are still counting because I
> haven't measured yet" is a defensible position; a coverage table claiming
> enforcement you cannot evidence is not.

## Why tune at all

`AWSManagedRulesCommonRuleSet` contains dozens of sub-rules. Some of them —
`SizeRestrictions_BODY`, `CrossSiteScripting_BODY`, `GenericRFI_QUERYARGUMENTS` —
fire on ordinary traffic in ways that depend entirely on your application.
Enabling the group at BLOCK without measuring is how you take a site down with a
rule that is working exactly as designed.

## Procedure

1. **Deploy dev** with the group in COUNT (its current state).

   ```bash
   make ENV=dev apply
   ```

2. **Generate mixed traffic** — attacks and legitimate requests, plus deliberately
   awkward-but-valid ones: Unicode, long query strings, base64 blobs, markdown in
   POST bodies. The `benign.yaml` catalog covers the awkward cases.

   ```bash
   wafops attack run   --env dev
   wafops falsepos run --env dev
   ```

3. **Query which sub-rules fired.** The nested field is the one that matters —
   `terminatingRuleId` alone only tells you the group name.

   ```
   fields @timestamp, httpRequest.clientIp as ip, httpRequest.uri as uri
   | filter @message like /AWSCommonRuleSet/
   | parse @message /"ruleId":"(?<subrule>[^"]+)"/
   | stats count(*) as hits by subrule
   | sort hits desc
   ```

4. **Classify every firing** as a true positive or a false positive.

5. **Add an override per noisy sub-rule** in `envs/*/rules.tf` — never disable the
   whole group:

   ```hcl
   rule_action_overrides = {
     SizeRestrictions_BODY = "COUNT"
   }
   ```

6. **Re-run and record before/after.**

7. **Flip `mode` to `BLOCK` in prod** with the table below filled in.

## Findings

| Sub-rule | Matched | True positives | False positives | Decision | Rationale |
|---|---:|---:|---:|---|---|
| *(to be measured)* | | | | | |

## Before / after

| Metric | COUNT baseline | After exclusions |
|---|---:|---:|
| Benign suite blocked | | |
| Attack suite blocked | | |
| WCU consumed | | |

## What would be different with production traffic

Notes to have ready, because this is the follow-up question:

- A one-hour synthetic sample is not a tuning window. Real tuning needs at least
  a week, and should span a weekly seasonality cycle.
- Rule changes should go out as a canary — a scope-down statement limiting the new
  BLOCK to a fraction of traffic by IP hash — before applying globally.
- Every promotion needs a rollback that is one `terraform apply` away, which is
  the case here because mode is data in `rules.tf`.
- Alarm on `AllowedRequests` collapsing, not only on blocks rising. That alarm
  exists in `modules/observability` for exactly this reason.
