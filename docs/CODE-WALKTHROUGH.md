# Code walkthrough

Read this before you touch anything. It explains what each file does and, more
usefully, *why it is shaped that way* — including the three or four decisions
that will get questioned in an interview.

---

## The one-sentence architecture

**Terraform owns everything that *is*. Python owns everything that *happens*.**

Buckets, distributions, Web ACLs, IP sets, alarms — Terraform. Attacks,
legitimate-traffic checks, log queries, evidence bundles — Python. Be able to say
that sentence; it is the cleanest justification for the rewrite.

---

## 1. `bootstrap/` — run once, by hand

This is the only configuration with **local state**, because it creates the
bucket every other configuration stores its state in. It cannot store its state
in a bucket that does not exist yet.

### `state.tf`
An S3 bucket with versioning, encryption, Block Public Access and a
`prevent_destroy` lifecycle rule. Versioning is the part that matters — it is
what makes a truncated or corrupted state recoverable.

**No DynamoDB lock table.** Terraform 1.11+ locks natively by writing a `.tflock`
object into the state bucket (`use_lockfile = true` in the backend block). Older
guides all tell you to create a DynamoDB table; it is no longer needed, and it
would have been an always-on resource in an otherwise ephemeral project. Worth
mentioning — it signals you are reading current docs rather than a 2021 blog post.

### `oidc.tf`
The centrepiece. Three roles:

| Role | Trusted subject | Can do |
|---|---|---|
| `WAFOpsPlanRole` | `repo:you/repo:pull_request`, `:ref:refs/heads/main` | Read everything, write the state lock |
| `WAFOpsApplyRole` | `repo:you/repo:environment:dev`, `:environment:prod` | Write, via the deploy policy |
| `WAFOpsDeployRole` | Your IAM user, MFA required | Same as apply, for local work |

**Why the split is the whole point.** GitHub only mints a token with an
`environment:` subject *after* that environment's protection rules are satisfied
— which is where the required human approval lives. A pull request token carries
a `pull_request` subject, so it can never match the apply role's trust policy, no
matter what the workflow file says. The gate is enforced by IAM, not by the CI
config, and CI config is the thing a malicious PR can edit.

**Why OIDC beats a stored key** (expect this question verbatim): the credential
is short-lived, scoped to one repository and one ref, and does not exist at rest.
There is no secret to leak from GitHub, a laptop, a screenshot, or a log.
Revocation is deleting a role rather than rotating a key everywhere it was used.

### `deploy-policy.tf`
Replaces "just use AdministratorAccess". Read the comments — the interesting part
is not that it is scoped but **where it cannot be**. `cloudfront:CreateDistribution`
has no ARN to scope to, because the ARN does not exist until the call succeeds.
S3 *is* scopable, so it is scoped to `wafops-*`. Saying which statements are
wildcards and why is a much better answer than pretending the whole policy is tight.

The trailing explicit `Deny` on `iam:*`, `ec2:RunInstances`, `guardduty:*` is a
belt-and-braces guard: an explicit deny beats any allow in IAM evaluation, so even
a future over-broad statement cannot let this role touch IAM or start compute.

> Expect to iterate on this policy. Apply, hit `AccessDenied`, add the one action,
> commit. **Keep those commits** — the history of narrowing a policy is itself the
> evidence that you did the work.

---

## 2. `modules/waf/` — the core

### `variables.tf` — rules as typed data

`var.rules` is a `list(object({name, priority, type, mode, config}))`. Each `type`
selects which WAFv2 statement gets built; `config` carries only that type's
attributes, declared with `optional()` and defaults.

**Why `config` is a typed object and not `any`.** This is a real Terraform gotcha
worth knowing. If `config` were `any`, Terraform would try to unify the element
types across the list, and rules with different config shapes would collide. A
single object type with optional attributes sidesteps that entirely and
self-documents at the same time.

**The validation blocks are the interesting part.** Five of them, and one is the
prototype's bug frozen into the type system:

```hcl
validation {
  condition     = alltrue([for r in var.rules : r.mode != "ALLOW"])
  error_message = "Terminating ALLOW rules are not permitted..."
}
```

In WAFv2 a terminating `Allow` **ends rule evaluation** for that request. The
prototype put an `Allow`-on-IP-set rule at priority 0, which silently disabled
every subsequent rule — injection, rate limiting, managed groups, all of it — for
any address in that set. This module makes that unrepresentable. The same
invariant is enforced again at plan level in
`policies/conftest/no_terminating_allow.rego`, so a hand-written resource cannot
reintroduce it either.

The others reject duplicate priorities and names (the API rejects them, but later
and with a worse message), reject `origin_check` rules with no allowed origins,
and reject `OrStatement`s with fewer than two children — because WAFv2 rejects
those at apply time, which is an expensive place to find out.

### `ip-sets.tf` — the `never_matches` trick

Three IP sets. The third, `never_matches`, is permanently empty and exists purely
so the module has **one code path instead of two**.

Every exemptible rule is written as:

```hcl
and_statement {
  statement { <the actual check> }
  statement { not_statement { ip_set_reference_statement { <exempt set> } } }
}
```

When a rule opts into exemption, `<exempt set>` is `trusted`. When it does not,
it is `never_matches` — an empty set matches nothing, so `NOT(nothing)` is always
true and the `AND` collapses to just the real check. Without this, every rule's
statement would have to be written out twice, once wrapped and once bare.

Cost: about 1 WCU per rule, out of a 1500 WCU default budget. Mention that
trade-off if asked — it shows you costed the abstraction.

`aws_wafv2_ip_set.blocked` has `lifecycle { ignore_changes = [addresses] }`,
because auto-remediation adds addresses at runtime. Without it, the next `apply`
would silently unblock everything blocked since the last one.

### `ip-sets.tf` — why regex pattern sets

Allowed origins and rate-limit URI scopes use `aws_wafv2_regex_pattern_set` rather
than an `OrStatement` of byte matches. Reason: WAFv2 rejects an `OrStatement` with
fewer than two children, so a config with exactly one allowed origin would fail at
apply. A regex set handles 1..N with no arity problem.

The rate-limit scope set falls back to the pattern `.*` when no URI prefixes are
given — again, one code path rather than conditionally emitting the block.

### `main.tf` — one `dynamic` block per rule type

WAFv2 statements are heterogeneous, so a single fully-generic dynamic block would
be unreadable. One block per type keeps every statement shape static and
greppable. Three structural facts drive the layout:

- **Custom rules use `action`; managed groups use `override_action`.** In an
  override block, `none {}` means "the group's own actions apply" (it blocks) and
  `count {}` means "count everything, block nothing".
- **A `rate_based_statement` cannot be nested inside And/Or/Not.** So its
  trusted-IP exemption and URI narrowing both live in its `scope_down_statement`.
- **A `managed_rule_group_statement` cannot be nested either.** Same solution: its
  own `scope_down_statement`.

`rule_action_override` is the tuning surface. It replaces the deprecated
`excluded_rules` argument and lets you downgrade one noisy sub-rule inside a
managed group to COUNT without disabling the whole group. This is where the
tuning report's findings land.

The two `custom_response_body` blocks matter more than they look: blocked
requests return a JSON body, and the test suite asserts on **that body**, not the
status code. See §5.

### `logging.tf`

The prototype never called `PutLoggingConfiguration`, so no request log existed
and its "threat detection" ran on `GetSampledRequests` — a bounded sample from a
short trailing window, not a log. Every count it produced was unreliable by
construction. This file is the fix, and everything in `detections/` depends on it.

Two things to know:

1. **The log group name must start with `aws-waf-logs-`.** AWS refuses any other
   name and the error does not tell you why.
2. **CloudWatch Logs, not Firehose → S3 → Athena.** Firehose is the right
   architecture at scale but bills continuously, which breaks the deploy-and-destroy
   posture. Logs Insights gives the same demonstration value for cents. Knowing
   *why* you chose the cheaper option is the point.

The `aws_cloudwatch_log_resource_policy` carries an `aws:SourceAccount` condition —
a confused-deputy guard, so the policy trusts the delivery service on behalf of
your account only.

---

## 3. `modules/static-site/` — the bypass fix

`s3.tf` is the most important file in the repository. Three things prevent the
prototype's defect, and all three are load-bearing:

1. **Block Public Access fully on** — no policy can ever make the bucket public.
2. **Origin Access Control** (not the legacy OAI) — CloudFront signs its origin
   requests with SigV4. OAC supports SSE-KMS and all regions; know the difference.
3. **An `aws:SourceArn` condition** pinning access to *this* distribution.

That third one is the part worth explaining. Without it the bucket policy trusts
the CloudFront *service* generally — meaning **any distribution in any AWS
account** could read your bucket. It is a real, published misconfiguration class,
and being able to explain it is worth more than the rest of the module.

Note what is deliberately **absent**: `aws_s3_bucket_website_configuration`. The
S3 *website* endpoint cannot be used with OAC and requires a public bucket. That
requirement is exactly how the prototype ended up public. This module uses the
REST endpoint (`bucket_regional_domain_name`) instead.

`cloudfront.tf` also drops the deprecated `forwarded_values` block for modern
cache and response-header policies, and adds HSTS/CSP/frame-options for free.
One honest limitation is commented in place: `minimum_protocol_version` cannot be
raised while using the default `*.cloudfront.net` certificate — enforcing TLS 1.2+
needs a custom domain with an ACM certificate.

The distribution carries a `lifecycle precondition` refusing to build without a
Web ACL. An unprotected origin is the defect this project exists to fix; the
config should not be able to express it.

---

## 4. `modules/alb-target/` — why dev exists

The listener's default action is `fixed-response`: the load balancer serves the
page itself. **No target group, no EC2, no container, no ECS cluster, nothing to
patch.** The ALB is a WAF attachment point and a response generator.

Why bother: a CloudFront distribution takes 15–20 minutes to deploy and about the
same to disable and delete, so tuning a rule against CloudFront costs a ~40 minute
round trip per iteration — which in practice means the rules never get tuned. The
ALB is up in ~90 seconds.

It also forces the WAF module to handle `REGIONAL` scope as well as `CLOUDFRONT`,
which is a more interesting piece of module design than either alone.

**The scope rule you must know:** a `CLOUDFRONT`-scoped Web ACL can only be
created in us-east-1. A `REGIONAL` one must live in the same region as the ALB /
API Gateway / AppSync resource it protects. Attachment also differs: REGIONAL uses
an explicit `aws_wafv2_web_acl_association`; CLOUDFRONT is attached the other way
round, by the distribution referencing the ACL in its `web_acl_id` argument (which
takes an **ARN**, despite the name).

---

## 5. `wafops/` — and the bug it exists to fix

### `verdict.py` — read this one properly

The prototype's harness did this:

```python
except requests.exceptions.ConnectionError:
    return {"blocked": True}
except Exception:
    return {"blocked": True}
```

A timeout, a DNS failure, or a distribution that had not finished deploying all
scored as *"the WAF blocked it"*. Since most tests expected a block, **those tests
passed**. The suite could report green against infrastructure that did not exist.

The replacement is a three-state verdict:

| Verdict | Meaning |
|---|---|
| `BLOCKED_BY_WAF` | 403/429 **and** the response carries the WAF's custom JSON body |
| `ALLOWED` | Reached the origin |
| `ERROR` | Transport failure. **Never** a pass, whatever the case expected |

The body check is the second half of the fix. A bare 403 could be S3 denying an
object, the ALB rejecting a malformed request, or a missing file — status code
alone cannot prove the WAF acted. `tests/test_verdict.py` covers all of it;
every one of those tests would have passed incorrectly under the original harness.

### `config.py`
Reads `terraform output -json` instead of a local `deployment_config.json`. Small
change, real architectural point: Terraform outputs become the contract between
infrastructure and tooling, so any machine that can reach the state can run the
tests.

### `payloads/*.yaml`
Attack vectors moved out of Python into data, with a `reference` (CVE/CWE) on
every entry. Note `cmdi-semicolon` has `expect: allowed` — command injection is an
application concern and the WAF is not expected to catch that shape. Declaring it
honestly beats quietly dropping the case.

`benign.yaml` is the suite that matters. Blocking attacks is easy — block
everything and you score 100%. Not blocking customers is the hard part. It
includes `python-requests/2.32.0`, which the prototype **blocked**, and whose own
test suite only escaped because it spoofed a Chrome user agent.

---

## 6. `policies/conftest/` — your own policies

Checkov and tfsec findings are table stakes. These four Rego policies encode
*this project's specific defects*, which is the part worth showing:

| Policy | Fails the build when |
|---|---|
| `no_public_buckets` | Any BPA setting is `false`, a bucket has no BPA, or a policy grants `Principal: "*"` |
| `waf_required` | A distribution has no `web_acl_id`, or an internet-facing ALB has no association |
| `logging_required` | A Web ACL exists with no logging configuration |
| `no_terminating_allow` | Any rule uses a terminating `Allow` action |

Each maps directly to a finding from the audit. That mapping is the story.

---

## 7. `envs/dev` vs `envs/prod`

Both are thin roots over the same modules. The single most useful thing you can
show someone is:

```bash
diff envs/dev/rules.tf envs/prod/rules.tf
```

Same rules, same priorities, different **modes** and thresholds. That diff *is*
the environment-promotion story.

`AWSCommonRuleSet` is still `COUNT` in prod, deliberately, and the README says so.
Promoting it without tuning data is how you take a site down with a rule that is
"working correctly". The procedure is in `docs/RULE-TUNING-REPORT.md`: run COUNT,
generate mixed traffic, group logs by sub-rule, add a `rule_action_overrides`
entry for each sub-rule firing on legitimate requests, *then* flip the mode.

Leaving it honest is the stronger move. "Two rules are still counting because I
haven't measured yet" is a senior answer. A coverage table claiming enforcement
you don't have is the fastest way to lose an interviewer's trust.

---

## 8. What to do first

```bash
make check          # fmt, validate, module tests, lint — no AWS needed
```

Then bootstrap, then dev, then read `docs/PLAN.md` §13 for the build sequence.

**Do not paste anything you cannot explain.** You will be asked about the
`never_matches` trick, the `aws:SourceArn` condition, why the whitelist rule was
dangerous, and why two rules are still in COUNT. Those four answers are most of
the interview.
