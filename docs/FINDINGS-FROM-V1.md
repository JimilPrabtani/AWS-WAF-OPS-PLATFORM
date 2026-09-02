# Findings from the prototype

An audit of [WAF-Ops-Suite](https://github.com/Akash-Bhavsar/WAF-Ops-Suite)
(4,941 lines, Python/boto3, MIT). Ordered by how much damage each does to the
project's core claim. Every one is fixed in this repository; the "Fixed by"
column says where.

---

## 1. Critical — the WAF could be bypassed entirely

**Where:** `deployment/01_deploy_infrastructure.py`

The script called `put_public_access_block` with all four settings `False`,
attached a bucket policy granting `s3:GetObject` to `Principal: "*"`, enabled S3
static website hosting, and created the CloudFront origin with
`S3OriginConfig.OriginAccessIdentity: ''` — no OAI, no OAC.

The bucket was therefore readable at its own S3 URL. Anyone who found it served
the same site with zero WAF rules in front of it. For a project whose thesis is
"AWS WAF protects this site", this invalidates the claim.

**Fixed by:** `modules/static-site/s3.tf` — BPA fully on, OAC, bucket policy with
an `aws:SourceArn` condition. Asserted by `wafops verify bypass` and by
`policies/conftest/no_public_buckets.rego`.

---

## 2. Critical — the whitelist rule disabled every other rule

**Where:** `src/waf_rules.py`, `WAFRuleSet.build_all_rules()` rule 0

`WhitelistTrustedIPs` sat at priority 0 with an `Allow` action. In WAFv2 a
terminating `Allow` **ends rule evaluation**, so any address in that set skipped
SQLi, XSS, rate limiting, bot detection and the managed rule groups. Documented
AWS behaviour, but as a default it means one over-broad CIDR silently turns the
WAF off for that range.

**Fixed by:** the `mode != "ALLOW"` validation in `modules/waf/variables.tf`,
plus `policies/conftest/no_terminating_allow.rego`. Trusted addresses are now a
`NotStatement` scope-down inside the individual rules that opt in.

---

## 3. High — no request logging existed

**Where:** nowhere — `put_logging_configuration` was never called

`ThreatDetector` built campaign detection, scanner detection and auto-blocking on
top of `get_sampled_requests`, which returns a bounded sample from a short
trailing window rather than a log. Every count, top-attacker list and campaign
conclusion drawn from it was unreliable by construction.

**Fixed by:** `modules/waf/logging.tf`, with header redaction. Everything in
`detections/` depends on it.

---

## 4. High — the CSRF rule did not prevent CSRF

**Where:** `src/waf_rules.py`, `csrf_rule`

Blocked POST/PUT/DELETE when the `x-csrf-token` header had size 0. The token was
never validated, because WAF has no session state to validate it against — so an
attacker sends `x-csrf-token: anything` and passes. Meanwhile every legitimate
client that does not set the header gets a 403. It cost availability and bought
no security.

**Fixed by:** replaced with `origin_check` in `modules/waf/main.tf`, which
validates something a WAF can actually assert. `docs/THREAT-MODEL.md` states the
limits.

---

## 5. High — connection errors were recorded as successful blocks

**Where:** `testing/test_waf_rules.py`, `_make_request`

Both exception handlers returned `{'blocked': True}`. A timeout, DNS failure, or
a distribution mid-deploy all scored as "the WAF blocked it" — and since most
tests expected a block, they passed. The suite could report green against
infrastructure that did not exist. Separately,
`blocked = status_code in (403, 429)` cannot distinguish a WAF block from an S3
403.

**Fixed by:** `wafops/src/wafops/verdict.py`, three-state verdict with `ERROR` as
a hard failure and a required custom-response-body match. Covered by
`wafops/tests/test_verdict.py`.

---

## 6. Medium — the OWASP coverage table overstated enforcement

`AWSManagedCoreRules` ran with `OverrideAction: Count` — blocking nothing — while
the README mapped it to A05 as though it enforced. A02 mapped to a CloudFront
HTTPS redirect, which is a transport setting rather than a WAF control.

**Fixed by:** the README coverage table now carries explicit dev/prod mode
columns, and two rules are openly marked as not yet promoted.

---

## 7. Medium — custom SQLi/XSS rules duplicated the managed group

Hand-built SQLi and XSS rules ran at BLOCK (priorities 4–5) while
`AWSManagedRulesCommonRuleSet` sat at COUNT — paying WCU for redundant coverage
while enforcing the weaker of the two. `OversizeHandling: CONTINUE` also meant
bodies past the inspection limit passed uninspected, undocumented.

**Fixed by:** removed. Managed groups first; custom rules only for a demonstrated
gap, documented.

---

## 8. Medium — bot detection blocked the project's own tooling

`bad_bot_rule` blocked on User-Agent substrings including `curl`, `wget` and
`python-requests` — the default UA of its own test suite, which only escaped
because it spoofed Chrome. Evaded by one flag; blocks legitimate automation.

**Fixed by:** kept as `ua_match`, permanently in COUNT, as a detection signal.
`benign.yaml` includes `python-requests/2.32.0` as a case that must be allowed.

---

## 9. Medium — auto-blocking had no expiry or unblock path

`auto_block_ip` added addresses to the blacklist forever. No TTL, no review
queue, no undo except editing by hand. On shared or CGNAT addresses that is a
permanent outage for innocent users.

**Fixed by:** planned as `modules/auto-remediation` with DynamoDB TTLs
(`docs/PLAN.md` phase 7). Note the gotcha recorded there: DynamoDB TTL deletion
is best-effort and can lag up to 48 hours, so the pruning Lambda must query by
`expires_at` rather than trust TTL deletion for correctness.

---

## 10. Medium — scripts exited 0 on failure and were not idempotent

`01_deploy_infrastructure.py`'s entrypoint called `deploy()` and discarded the
return value, so a failed deployment still exited 0 — any CI wrapper would call
it a success. Errors were caught as bare `except Exception`, printed, and
converted to `False`, losing the reason. Bucket names were timestamped, so
re-running created a new bucket rather than converging, and state lived in a
gitignored local JSON file.

**Fixed by:** the migration itself. This is the strongest single argument for it.

---

## 11. Minor

- Legacy `forwarded_values` on the distribution instead of cache / origin-request
  policies. **Fixed** in `modules/static-site/cloudfront.tf`.
- No response headers policy — HSTS, CSP and `X-Content-Type-Options` were free
  wins left on the table. **Fixed.**
- Both CloudWatch alarms created with `ActionsEnabled: False` and no SNS topic,
  so they could never notify anyone. **Fixed** in `modules/observability`.
- `datetime.utcnow()`, deprecated from Python 3.12.
- Geo-blocking RU/CN/KP/IR presented as a security control; any VPN defeats it.
  **Fixed** by reframing it as noise reduction in the README and threat model.
- Single squashed commit, so the history showed no build.
