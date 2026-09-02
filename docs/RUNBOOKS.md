# Runbooks

Three scenarios. Each is written to be followed at 2am by someone who did not
build this.

---

## 1. A legitimate user is being blocked

**Symptom:** a report that the site returns 403 with
`{"error": "blocked"}`, or the `wafops-*-waf-allowed-collapse` alarm fires.

**Triage**

1. Get the user's public address and an approximate time.
2. Find the terminating rule:

   ```
   fields @timestamp, httpRequest.clientIp as ip, terminatingRuleId as rule, httpRequest.uri
   | filter ip = "203.0.113.9"
   | filter action = "BLOCK"
   | sort @timestamp desc
   | limit 20
   ```

**Contain** — pick the narrowest option that works:

- *One user, urgent:* add them to `trusted_ip_cidrs` in `envs/prod/terraform.tfvars`
  and apply. Note this only exempts them from rules with `exempt_trusted_ips`,
  which is the intended blast radius.
- *One managed sub-rule, many users:* add a `rule_action_overrides` entry setting
  that sub-rule to `COUNT`, and apply.
- *A whole rule is wrong:* change its `mode` to `COUNT` in `envs/prod/rules.tf`
  and apply. One-line change, one-line revert.

**Recover.** Record the case in `docs/RULE-TUNING-REPORT.md` and add the request
shape to `wafops/src/wafops/payloads/benign.yaml` so it is a permanent regression
test. A false positive that does not become a test case will recur.

---

## 2. Scanner sweep

**Symptom:** the `scanner_sweep` detection alarm fires.

**Triage**

```
fields @timestamp, httpRequest.clientIp as ip, httpRequest.uri as uri
| filter action = "BLOCK"
| stats count_distinct(uri) as paths, count(*) as hits by ip
| sort paths desc
| limit 20
```

**Decide.** A single source with many distinct paths is a scanner. Many sources
each with few paths is *not* — that is a distributed pattern, and blocking it by
address will hit real users.

**Contain (single source only)**

```bash
wafops ipset block 198.51.100.7 --ttl 24h --reason "scanner-sweep: 400 distinct paths in 5m"
```

The TTL matters. An indefinite block on a shared or CGNAT address is a permanent
outage for people who did nothing.

**Recover.** Confirm nothing succeeded — check `AllowedRequests` from that source
for 2xx responses to unusual paths.

---

## 3. Origin bypass suspected

**Symptom:** the `origin-bypass` assertion fails in CI, or the origin bucket shows
traffic that did not come through CloudFront.

This is the failure mode this project exists to prevent. Treat it as an incident.

**Triage**

```bash
terraform -chdir=envs/prod output origin_bypass_url
curl -sS -o /dev/null -w '%{http_code}\n' "$(terraform -chdir=envs/prod output -raw origin_bypass_url)"
```

Anything other than `403` is a confirmed bypass.

**Contain immediately**

```bash
aws s3api put-public-access-block --bucket <bucket> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

**Then find out how it happened.** Terraform should have prevented it, so either
someone changed it out of band (check CloudTrail for `PutBucketPolicy` and
`PutPublicAccessBlock`) or a policy gap let it through. If the latter, the fix is
a new case in `policies/conftest/no_public_buckets.rego`, not just a re-apply.

**Recover.** `terraform apply` to restore declared state, then re-run
`wafops verify bypass` to confirm.
