# WAF Ops Platform — Build Plan

**A Terraform-first, dual-scope AWS WAF platform with detection-as-code, OIDC-federated CI/CD, and a deploy-and-destroy cost model.**

Version 1.0 · Planning document · Nothing in here has been executed yet.

---

## 0. Provenance — read this first

This project starts from [Akash-Bhavsar/WAF-Ops-Suite](https://github.com/Akash-Bhavsar/WAF-Ops-Suite), a friend's Python/boto3 prototype, which is MIT licensed. You are building your own version in your own repository.

**How to handle this honestly, because it is actually an advantage:**

- New repository under your account. Suggested name: `waf-ops-platform` (or `edge-waf-platform`). Not a GitHub fork — a fork shows someone else's name at the top of the page forever and buries your commit history under theirs.
- Keep a `LICENSE` file with MIT. If you carry over any of the original code substantially (most likely the attack-vector payload lists and parts of the false-positive suite), preserve the original copyright line and add your own.
- Put a short `## Credits` section at the bottom of the README: "Started from a Python/boto3 prototype by [Akash Bhavsar](link), rebuilt as Terraform with a corrected security model."
- Ask your friend before publishing. Takes one message and removes any ambiguity.

**Why this is an advantage:** the strongest interview story available to you is *"I took an existing WAF project, audited it, found a complete WAF bypass in the origin configuration, and rebuilt it as Terraform with the bypass fixed and evidence-based rule tuning."* That is a real engineering narrative. Pretending you wrote the prototype gets you nothing and risks a lot.

**One rule for the whole build:** you will be interviewed on this. Do not paste anything you cannot explain. Every rule, every IAM condition, every exclusion needs a reason you can say out loud. Where this plan gives you a decision, understand *why* before you implement it.

---

## 1. What this project claims

> A production-shaped AWS WAF platform defined entirely in Terraform, deployable to either a regional ALB or a CloudFront distribution from the same module, with WAF rule tuning driven by logged evidence rather than assertion, deployed by a least-privilege role via GitHub OIDC with no stored credentials, and costing effectively nothing at rest.

Every clause in that sentence has to be defensible. Cut any clause you don't build.

### What it deliberately does not claim

- Not a DDoS solution (that's Shield Advanced, and it costs $3,000/month).
- Not bot management (that's Bot Control, $10/ACL/month plus per-request).
- Not a WAF that has seen real production traffic. Say "synthetic traffic I generated" every time.

Naming your limits is the single cheapest credibility win in the whole project.

---

## 2. Target architecture

```
                    ┌──────────────── prod (CLOUDFRONT scope, us-east-1) ────────────┐
                    │                                                                │
  Internet ──────► CloudFront ──► WAF Web ACL ──► S3 origin (OAC, BPA on, private)   │
                    │                  │                                             │
                    └──────────────────┼─────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┼──── dev (REGIONAL scope, any region) ───────┐
                    │                  │                                             │
  Internet ──────► ALB ──────────► WAF Web ACL ──► fixed-response listener            │
                    │                  │           (no EC2, no ECS, no targets)      │
                    └──────────────────┼─────────────────────────────────────────────┘
                                       │
                                       ▼
                         CloudWatch Logs (aws-waf-logs-*)
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
      Logs Insights           Metric filters →         EventBridge → Lambda
      detection queries       CloudWatch alarms        → DynamoDB (block TTLs)
      (detections/*.yaml)     → SNS                    → WAF IP set prune
```

### The dev-environment trick worth understanding

The dev environment uses an ALB whose listener has a **`fixed-response` default action** — it returns a small HTML page directly from the load balancer. There is no target group, no EC2 instance, no container, no VPC to build (use the default VPC via a data source).

Why this matters: a CloudFront distribution takes 15–20 minutes to deploy and about the same to disable and delete. Tuning a WAF rule against CloudFront means a 40-minute round trip per iteration, which means you will not actually tune anything. An ALB comes up in roughly 90 seconds. You do all your rule development against dev, and promote a validated rule set to prod.

This also forces the WAF module to support both `REGIONAL` and `CLOUDFRONT` scope cleanly, which is a genuinely interesting piece of module design and a good thing to be asked about.

**The scope constraint you must know:** a Web ACL with `scope = "CLOUDFRONT"` must be created in `us-east-1`, no exceptions. A Web ACL with `scope = "REGIONAL"` must live in the same region as the ALB/API Gateway/AppSync resource it protects. This is why the root modules pin providers per environment.

---

## 3. Repository layout

```
waf-ops-platform/
├── README.md
├── LICENSE
├── Makefile                          # deploy / test / evidence / destroy
├── .github/
│   └── workflows/
│       ├── validate.yml              # fmt, validate, tflint, checkov, conftest, pytest
│       ├── plan.yml                  # OIDC plan role, plan posted as PR comment
│       ├── apply.yml                 # OIDC apply role, gated by GitHub environment
│       ├── e2e.yml                   # deploy dev → attack suite → destroy
│       └── drift.yml                 # scheduled: fail loudly if anything is still running
│
├── bootstrap/                        # run ONCE, by hand, separate state
│   ├── main.tf                       # state bucket, GitHub OIDC provider, deploy roles
│   ├── iam-plan-role.tf
│   ├── iam-apply-role.tf
│   ├── variables.tf
│   └── README.md                     # exact one-time bootstrap runbook
│
├── modules/
│   ├── waf/                          # THE core module — dual scope
│   │   ├── main.tf                   # web ACL, dynamic rule blocks
│   │   ├── rules.tf                  # rule construction from var.rules
│   │   ├── ip-sets.tf
│   │   ├── logging.tf                # logging config + redaction
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── versions.tf
│   │   └── tests/waf.tftest.hcl
│   │
│   ├── static-site/                  # prod edge: S3 + CloudFront + OAC
│   │   ├── s3.tf                     # BPA fully on, no public policy, ever
│   │   ├── cloudfront.tf             # OAC, cache policy, response headers policy
│   │   ├── policies.tf               # bucket policy scoped to distribution ARN
│   │   └── tests/static-site.tftest.hcl
│   │
│   ├── alb-target/                   # dev edge: ALB with fixed-response listener
│   │   ├── main.tf
│   │   └── variables.tf
│   │
│   ├── observability/
│   │   ├── log-group.tf              # MUST be named aws-waf-logs-*
│   │   ├── dashboard.tf
│   │   ├── metric-filters.tf         # generated from detections/*.yaml
│   │   ├── alarms.tf                 # ActionsEnabled = true, wired to SNS
│   │   └── sns.tf
│   │
│   └── auto-remediation/             # optional, phase 4
│       ├── dynamodb.tf               # ip → expires_at, TTL enabled
│       ├── lambda.tf
│       ├── eventbridge.tf
│       └── src/prune.py
│
├── envs/
│   ├── dev/                          # REGIONAL scope, ALB, rules in COUNT
│   │   ├── main.tf
│   │   ├── backend.tf
│   │   ├── providers.tf
│   │   └── terraform.tfvars
│   └── prod/                         # CLOUDFRONT scope, us-east-1, rules in BLOCK
│       ├── main.tf
│       ├── backend.tf
│       ├── providers.tf
│       └── terraform.tfvars
│
├── policies/
│   ├── conftest/                     # YOUR custom OPA policies
│   │   ├── no_public_buckets.rego
│   │   ├── waf_required.rego
│   │   ├── logging_required.rego
│   │   └── no_terminating_allow.rego
│   └── iam/
│       ├── deploy-plan-policy.json    # least privilege, read
│       └── deploy-apply-policy.json   # least privilege, write
│
├── detections/                       # detection-as-code
│   ├── scanner-sweep.yaml
│   ├── credential-stuffing.yaml
│   ├── enumeration-burst.yaml
│   └── README.md                     # the detection engineering rationale
│
├── wafops/                           # Python CLI package
│   ├── pyproject.toml
│   ├── src/wafops/
│   │   ├── __init__.py
│   │   ├── cli.py                    # typer app, entry point
│   │   ├── config.py                 # reads `terraform output -json`
│   │   ├── verdict.py                # was this a WAF block? (the important one)
│   │   ├── payloads/                 # attack vector catalogs, as data
│   │   │   ├── sqli.yaml
│   │   │   ├── xss.yaml
│   │   │   ├── traversal.yaml
│   │   │   └── benign.yaml
│   │   ├── commands/
│   │   │   ├── attack.py
│   │   │   ├── falsepos.py
│   │   │   ├── logs.py
│   │   │   ├── ipset.py
│   │   │   └── report.py
│   │   └── analysis/
│   │       ├── insights.py           # Logs Insights query runner
│   │       └── tuning.py             # count-mode → exclusion recommendations
│   └── tests/                        # pytest, all offline with fixtures
│
└── docs/
    ├── ARCHITECTURE.md
    ├── THREAT-MODEL.md               # MITRE ATT&CK mapping, honest scoping
    ├── RULE-TUNING-REPORT.md         # the evidence artifact — see §7
    ├── RUNBOOKS.md                   # 3 incident scenarios
    ├── COST-MODEL.md
    ├── IAM-DESIGN.md
    └── FINDINGS-FROM-V1.md           # the bypass and the other defects you fixed
```

---

## 4. The WAF module — design

This is the piece the whole project is judged on. Get the interface right and everything else follows.

### 4.1 Interface

```hcl
module "waf" {
  source = "../../modules/waf"

  name  = "wafops-dev"
  scope = "REGIONAL"          # or "CLOUDFRONT"

  # Rules are DATA, not code. This is the design decision to defend.
  rules = var.rules

  trusted_ip_cidrs = ["203.0.113.4/32"]
  blocked_ip_cidrs = []

  logging = {
    enabled          = true
    retention_days   = 7
    redacted_headers = ["authorization", "cookie", "x-api-key"]
  }

  tags = local.tags
}
```

### 4.2 Rules as a typed variable

The single best structural idea carried over from the prototype's `WAFRuleBuilder` is that a rule set is data. In Terraform, express that as a typed object list validated by `variable` validation blocks, and build the ACL with `dynamic` blocks.

Sketch:

```hcl
variable "rules" {
  type = list(object({
    name     = string
    priority = number
    type     = string           # managed | rate_limit | ip_set | geo | sqli | xss | byte_match | origin_check
    mode     = string           # BLOCK | COUNT | ALLOW
    config   = any
  }))

  validation {
    condition     = length(distinct([for r in var.rules : r.priority])) == length(var.rules)
    error_message = "WAF rule priorities must be unique."
  }

  validation {
    condition     = alltrue([for r in var.rules : contains(["BLOCK", "COUNT", "ALLOW"], r.mode)])
    error_message = "Rule mode must be BLOCK, COUNT, or ALLOW."
  }

  validation {
    # The v1 bug: a terminating ALLOW at low priority disables everything after it.
    condition     = length([for r in var.rules : r if r.mode == "ALLOW"]) == 0
    error_message = "Terminating ALLOW rules are not permitted. Reference trusted IPs as a NotStatement scope-down inside specific rules instead."
  }
}
```

That last validation block is worth writing purely because it encodes the exact bug from v1 as a machine-checked invariant. It's a two-minute demo in an interview.

### 4.3 The corrected rule ladder

WAF evaluates in priority order; the first terminating match wins. The numbering *is* the logic.

| Pri | Rule | dev mode | prod mode | Notes |
|-----|------|----------|-----------|-------|
| 10 | `BlockedIPs` | BLOCK | BLOCK | Fed by auto-remediation, entries carry a TTL |
| 20 | `RateLimit` | COUNT | BLOCK | Scope-down to expensive paths; trusted IPs excluded via `NotStatement` here, not globally |
| 30 | `AWSManagedCommonRuleSet` | COUNT | BLOCK | Promoted to BLOCK only with tuning evidence (§7) |
| 40 | `AWSManagedKnownBadInputs` | BLOCK | BLOCK | Best value-per-WCU rule available. Log4Shell, SSRF, path traversal |
| 50 | `AWSManagedAnonymousIpList` | COUNT | COUNT | VPN/Tor/hosting ranges. Keep in COUNT — high false-positive risk |
| 60 | `GeoRestriction` | COUNT | BLOCK | Documented as noise reduction, **not** a security boundary |
| 70 | `OriginValidation` | COUNT | BLOCK | Replaces v1's fake CSRF rule: state-changing methods must carry a known `Origin`/`Referer` |
| 80 | `SuspiciousUserAgents` | COUNT | COUNT | Stays in COUNT permanently. Trivially evaded; useful as a signal, not a control |

**Deliberately removed from v1:**

- `WhitelistTrustedIPs` at priority 0 — a terminating `Allow` that disabled every subsequent rule for whitelisted IPs. Trusted IPs now appear as a `NotStatement` scope-down inside rules 20 and 60 only.
- `SQLInjectionProtection` / `XSSProtection` custom rules — redundant with `AWSManagedCommonRuleSet` once it is in BLOCK. Removing them saves WCU and removes the "why are you enforcing your hand-rolled version while the managed one is in count mode?" question. Re-add one *only* if tuning data shows a real gap, and document the gap.
- `CSRFProtection` — blocked mutating requests lacking a non-empty `x-csrf-token` header. WAF has no session state, so the token was never validated and any attacker could send `x-csrf-token: x`. Replaced with `OriginValidation`, and `docs/THREAT-MODEL.md` states plainly that real CSRF defence is SameSite cookies plus server-side token validation.

Eight rules with reasons beats ten rules as a badge. Do not add rules to make the number bigger.

### 4.4 Logging

```hcl
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.name}"   # the prefix is MANDATORY
  retention_in_days = var.logging.retention_days
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  dynamic "redacted_fields" {
    for_each = var.logging.redacted_headers
    content {
      single_header { name = redacted_fields.value }
    }
  }
}
```

Two things to know and be able to say:

1. **The `aws-waf-logs-` prefix on the log group name is required by AWS.** Deployment fails without it, and the error message is unhelpful.
2. **CloudWatch Logs, not Firehose.** Firehose + S3 + Athena is the "proper" architecture at scale, but it means always-on cost and it does not fit a deploy-and-destroy posture. Logs Insights gives you the same demonstration value for cents. Say this explicitly in `COST-MODEL.md` — knowing *why* you chose the cheaper option is the point.

---

## 5. The static-site module — fixing the bypass

This module exists to correct v1's central defect. v1 disabled all four Block Public Access settings, attached an `s3:GetObject` policy granting `Principal: "*"`, enabled S3 website hosting, and created the CloudFront origin with an empty `OriginAccessIdentity` — so the bucket was directly reachable and the WAF could be skipped entirely.

The corrected shape:

```hcl
resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${var.name}-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_iam_policy_document" "site" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site.arn]
    }
  }
}
```

Points to understand, because they are all askable:

- **OAC, not OAI.** OAI is the legacy mechanism; OAC supports SSE-KMS and all regions. Know the difference.
- **The `AWS:SourceArn` condition is what makes this tight.** Without it, the policy trusts the CloudFront *service*, meaning any CloudFront distribution in any AWS account could read your bucket. This is a real, published misconfiguration class — being able to explain it is worth more than the rest of the module.
- **Use the REST endpoint, not the S3 website endpoint.** The website endpoint (`bucket.s3-website-region.amazonaws.com`) does not support OAC at all and requires a public bucket. That's how v1 ended up public. Use `bucket.s3.region.amazonaws.com` with `origin_access_control_id` set.
- **Drop the legacy `forwarded_values` block.** Use `aws_cloudfront_cache_policy` and `aws_cloudfront_origin_request_policy` (or the AWS-managed `CachingOptimized` policy).
- **Add `aws_cloudfront_response_headers_policy`** with HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a Referrer-Policy and a CSP. Free, and a visible security win the console screenshots will show.
- **Set `minimum_protocol_version = "TLSv1.2_2021"`** on the viewer certificate.

### The proof test

Write a test that asserts the direct S3 REST URL returns 403 while the CloudFront URL returns 200. Run it in CI. This is the single highest-value test in the repository, because it proves the WAF cannot be bypassed — which is the project's core claim.

---

## 6. Identity and access — the DevSecOps centerpiece

v1's answer was `aws configure` with static keys and a README note saying "AdministratorAccess works for demo purposes." Replacing that is one of the most legible upgrades available.

### 6.1 Local development — assume a role

Create `WAFOpsDeployRole` with a scoped policy and a trust policy allowing your IAM user to assume it. Then in `~/.aws/config`:

```ini
[profile wafops-admin]
region = us-east-1

[profile wafops-deploy]
role_arn       = arn:aws:iam::<ACCOUNT_ID>:role/WAFOpsDeployRole
source_profile = wafops-admin
region         = us-east-1
```

Run everything with `AWS_PROFILE=wafops-deploy`. Both `terraform` and `aws` pick it up automatically. Enforce MFA on the assume-role with an `aws:MultiFactorAuthPresent` condition and mention it in `IAM-DESIGN.md`.

### 6.2 CI — GitHub OIDC, zero stored credentials

Create an IAM OIDC identity provider for `token.actions.githubusercontent.com`, then **two** roles:

| Role | Used by | Permissions | Trust condition on `sub` |
|------|---------|-------------|--------------------------|
| `WAFOpsPlanRole` | plan.yml, on every PR | Read-only + state read | `repo:<you>/waf-ops-platform:pull_request` |
| `WAFOpsApplyRole` | apply.yml, gated | Write | `repo:<you>/waf-ops-platform:environment:prod` |

Both require `aud = sts.amazonaws.com`. The split matters: a pull request from a fork can trigger a plan but can never reach the apply role, because the apply role only trusts the `environment:prod` subject, and GitHub environments require a human approval before issuing that token.

Be ready to explain **why OIDC beats stored keys**: the token is short-lived, scoped to one repository and one ref, and there is no secret that can leak from GitHub, a laptop, or a screenshot. This is a standard interview question and most candidates can only say "it's more secure."

### 6.3 Least-privilege policy

Write `policies/iam/deploy-apply-policy.json` by hand. Start from the list of resources Terraform actually creates. Expect to iterate: run `terraform apply`, hit an `AccessDenied`, add the one action, commit. **Keep those commits** — the history of narrowing a policy is itself evidence of the practice, and it's a nicer artifact than a finished policy that appeared in one commit.

---

## 7. The rule tuning report — your differentiator

Most WAF portfolio projects assert coverage. Almost none show tuning. This document is what separates yours.

**The method:**

1. Deploy dev with `AWSManagedCommonRuleSet` in COUNT mode.
2. Generate mixed traffic — the attack suite plus the benign suite plus some deliberately awkward-but-legitimate requests (Unicode, long query strings, base64 blobs, markdown in a POST body).
3. Query the WAF logs with Logs Insights, grouping by `terminatingRuleId` and `ruleGroupList[].terminatingRule.ruleId` to see which *sub-rules* inside the managed group fired.
4. For every managed sub-rule that fired on benign traffic, decide: exclude it, scope it down, or accept the false positive. Write down the reasoning.
5. Apply the exclusions, re-run, show before/after numbers.
6. Promote to BLOCK in prod with the evidence attached.

**What `docs/RULE-TUNING-REPORT.md` contains:**

- A table: managed sub-rule → requests matched → true positives → false positives → decision → rationale.
- The exact Logs Insights queries used, so it's reproducible.
- Before/after block rates on the benign suite.
- A short "what I'd need to do differently with real production traffic" section — sampling windows, canary deployment of rule changes, a rollback plan.

That last section is what makes it read as an engineer rather than a student.

---

## 8. Detection-as-code

Each file in `detections/` is a versioned detection with its reasoning attached:

```yaml
id: scanner-sweep
name: Directory enumeration sweep
severity: medium
rationale: >
  Automated scanners request many distinct non-existent paths from one source
  in a short window. Distinct-URI count per client IP separates this from a
  normal user browsing, who revisits a small set of paths.
query: |
  fields @timestamp, httpRequest.clientIp as ip, httpRequest.uri as uri
  | filter action = "BLOCK" or terminatingRuleId != "Default_Action"
  | stats count_distinct(uri) as paths, count(*) as hits by ip, bin(5m)
  | filter paths > 25
  | sort paths desc
threshold:
  distinct_paths: 25
  window: 5m
tuning_notes: >
  Threshold set from observed benign traffic in dev, where the highest legitimate
  distinct-path count over 5m was 9. 25 leaves headroom for a crawler.
false_positives:
  - Search engine crawlers. Mitigate by excluding verified crawler IP ranges.
  - Site-wide link checkers run by the site owner.
response: Add source IP to the blocked set with a 24h TTL.
```

A small script converts these into CloudWatch metric filters and alarms at apply time, so the YAML is the single source of truth. Writing a threshold and then *justifying it from measured data* is the whole point — a hardcoded `> 100` with no explanation is the thing you are trying not to be.

Three detections is enough. Four is fine. Ten shallow ones is worse than three deep ones.

---

## 9. The Python CLI package

Terraform owns everything that *is*. Python owns everything that *happens*. Be able to state that division in one sentence.

### Package

`pyproject.toml`, package name `wafops`, console entry point `wafops`. Use `typer` for the CLI and `rich` for output — the terminal screenshots end up in your README, so they should look good.

### Commands

| Command | Does |
|---------|------|
| `wafops attack run --env dev` | Runs the attack vector catalogs against the deployed target |
| `wafops falsepos run --env dev` | Runs the benign traffic suite — **the important one** |
| `wafops logs query <detection-id>` | Runs a detection's Logs Insights query and renders results |
| `wafops tuning analyze` | Reads COUNT-mode logs, recommends exclusions |
| `wafops ipset block <ip> --ttl 24h` / `unblock` / `list` | Manual IP set operations with TTLs |
| `wafops report generate` | Produces the evidence bundle (§11) |

### Config comes from Terraform, not a local JSON file

v1 kept state in a gitignored `deployment_config.json` that no second machine or CI runner would ever have. Replace it:

```python
def load_env(env: str) -> EnvConfig:
    raw = subprocess.run(
        ["terraform", "-chdir=envs/" + env, "output", "-json"],
        capture_output=True, check=True, text=True,
    ).stdout
    return EnvConfig.model_validate(
        {k: v["value"] for k, v in json.loads(raw).items()}
    )
```

Terraform outputs are now the contract between infrastructure and tooling. Small change, real architectural point.

### `verdict.py` — fix the v1 test bug here

v1's `_make_request` returned `blocked: True` from both exception handlers, so a timeout or a DNS failure scored as "the WAF blocked it," and since most tests expected a block, they passed. The suite could go green against infrastructure that did not exist.

The replacement is a three-state verdict:

```python
class Verdict(str, Enum):
    BLOCKED_BY_WAF = "blocked_by_waf"   # 403/429 AND the custom response body matched
    ALLOWED        = "allowed"          # 2xx/3xx from the origin
    ERROR          = "error"            # timeout, DNS, connection reset — NEVER a pass
```

`BLOCKED_BY_WAF` must require the custom JSON response body you configure on the block action (`{"error":"blocked", ...}`), not merely a 403 status — a plain 403 could be S3, the ALB, or a missing object. `ERROR` fails the test run with a non-zero exit. Unit-test all three paths with mocked responses; this is your best pytest example.

### Payloads as data

Move the attack vectors out of Python into `payloads/*.yaml` with fields for `id`, `category`, `payload`, `location` (query/body/uri/header/cookie), `expect`, and `reference` (CVE, OWASP, or CWE link). Now the catalog is reviewable by someone who doesn't read Python, and it's trivially extensible.

### Tests

All pytest tests run **offline** against fixtures. Nothing in the unit suite should touch AWS. Cover: verdict classification, payload catalog schema validation, Logs Insights response parsing, TTL expiry math, config loading from terraform output JSON. Target something like 25–40 real tests. Terraform-side invariants (unique priorities, no terminating ALLOW, logging always enabled) belong in `.tftest.hcl` files and Conftest policies, not pytest.

---

## 10. CI/CD

### `validate.yml` — every push

`terraform fmt -check` → `terraform validate` → `tflint` → `checkov` → `conftest test` against your custom Rego → `ruff` → `pytest`. No AWS credentials needed at all for most of this.

### `plan.yml` — every PR

Assumes `WAFOpsPlanRole` via OIDC, runs `terraform plan` for both envs, posts the plan as a PR comment, and attaches an Infracost diff. Reviewers see cost and change in the same place.

### `apply.yml` — manual approval

Assumes `WAFOpsApplyRole`, gated behind a GitHub Environment with a required reviewer (you). Apply only runs after approval.

### `e2e.yml` — the good one

Deploy dev → wait for the ALB → run `wafops attack run` and `wafops falsepos run` → assert the direct-S3-403 test → publish the report as an artifact → `terraform destroy` in an `always()` step so a failure never leaves resources running. **A WAF change that breaks legitimate traffic fails the build.** That sentence is worth putting in the README.

### `drift.yml` — the cost guard

Scheduled daily: enumerate WAF Web ACLs, ALBs and CloudFront distributions tagged `project=waf-ops-platform`, and fail the workflow if any exist. Turns your budget constraint into a demonstrated engineering control rather than a limitation.

### Custom Conftest policies

Write these yourself against the Terraform plan JSON — off-the-shelf Checkov findings are table stakes, your own policies are the signal:

- `no_public_buckets.rego` — fail if any `aws_s3_bucket_public_access_block` sets any field to `false`.
- `waf_required.rego` — fail if a `cloudfront_distribution` or `lb_listener` is created without an associated Web ACL.
- `logging_required.rego` — fail if a `aws_wafv2_web_acl` exists without a logging configuration.
- `no_terminating_allow.rego` — fail on any rule with an `allow` action. **This is the v1 bypass, encoded as policy.**

---

## 11. Evidence bundle

`wafops report generate` writes a timestamped JSON + Markdown bundle capturing: rules active and their modes, logging enabled and retention, alarm states, attack-suite results, false-positive-suite results, the direct-origin 403 proof, WCU consumption per rule, and estimated cost of the run.

Two reasons this earns its place. First, it's exactly what an auditor asks for, and it makes the compliance story concrete rather than aspirational. Second, since you tear the environment down, the bundle plus screenshots is the only durable proof the thing worked — commit it to `docs/evidence/`.

---

## 12. Cost model

Verified against AWS pricing at time of writing (us-east-1) — re-check before publishing, prices change.

| Component | Rate | Basis |
|-----------|------|-------|
| WAF Web ACL | $5.00 / month, **prorated hourly** | $0.0068 / hr |
| WAF rule or managed rule group | $1.00 / month each, prorated hourly | 8 rules ≈ $0.0110 / hr |
| WAF requests | $0.60 / million | A full test run ≈ $0.0003 |
| ALB (dev) | $0.0225 / hr + $0.008 / LCU-hr | ≈ $0.024 / hr at test volumes |
| CloudFront (prod) | Free tier covers this workload | ≈ $0 |
| CloudWatch Logs | Ingest + short retention | Cents per run |
| S3 (state + site) | A few MB | ≈ $0.01 / month |

**Derived figures for the README:**

- **dev environment while running:** ≈ **$0.042 / hour**. An eight-hour working session is about **$0.34**.
- **prod validation cycle:** ≈ **$0.019 / hour** plus ~40 minutes of CloudFront deploy/destroy overhead. A three-hour window is roughly **$0.06**.
- **At rest, everything destroyed:** ≈ **$0.01 / month** for the state bucket.
- **A complete end-to-end validation cycle: under $1.**

Put a `COST-MODEL.md` in the repo with this table, the arithmetic shown, and the sources linked. Very few candidates cost their own project, and none of them show the math.

Add a `WCU` section too: report the Web ACL's capacity consumption per rule and note which rules earn their capacity. WAF capacity units are something almost nobody thinks about, and mentioning them signals real operational exposure.

---

## 13. Build sequence

Commit at every step. The history is part of the deliverable — v1's single squashed commit reads as a code drop, and yours should read as a build.

### Phase 0 — Repo and bootstrap (half a day)
Fresh repo, MIT license with credits, README skeleton, `.gitignore`, `Makefile` stub. Then `bootstrap/`: state bucket with versioning, S3 native state locking (`use_lockfile = true`, Terraform ≥ 1.11 — no DynamoDB lock table needed any more), OIDC provider, plan and apply roles. Run it once by hand and write the runbook while you do.

### Phase 1 — The WAF module and dev environment (2–3 days)
`modules/waf` with dual scope and rules-as-data. `modules/alb-target` with the fixed-response listener. `envs/dev`. Get one full `apply` → curl a blocked payload → see it in the logs → `destroy` cycle working. **Do not move on until the deploy/destroy loop is fast and reliable** — everything after this depends on iterating quickly.

### Phase 2 — The CLI and the test loop (2–3 days)
`wafops` package, payload catalogs as YAML, `verdict.py` with its three states, attack and false-positive commands, pytest suite offline. Wire `validate.yml` in CI.

### Phase 3 — Prod edge and the bypass fix (2 days)
`modules/static-site` with OAC, BPA on, `AWS:SourceArn` condition, response headers policy. `envs/prod`. Write the direct-S3-403 proof test and put it in CI. Then write `docs/FINDINGS-FROM-V1.md` while it's fresh.

### Phase 4 — Observability and detections (2–3 days)
WAF logging, log group, dashboard, SNS-wired alarms with `ActionsEnabled = true`. Three detections in `detections/` with real thresholds derived from measured traffic. `wafops logs query`.

### Phase 5 — Tuning and promotion (2 days)
Run the COUNT-mode experiment, produce `RULE-TUNING-REPORT.md`, apply exclusions, promote managed rules to BLOCK in prod with the evidence attached.

### Phase 6 — Full pipeline (1–2 days)
`plan.yml`, `apply.yml`, `e2e.yml`, `drift.yml`. Custom Conftest policies. Infracost. Get a real PR that shows plan output, scan results, and cost diff as comments — screenshot it.

### Phase 7 — Auto-remediation (2 days, optional)
DynamoDB with TTL, prune Lambda, EventBridge schedule, audit log. **Note the gotcha:** DynamoDB TTL deletion is best-effort and can lag by up to 48 hours, so the Lambda must query by `expires_at` rather than trusting TTL deletion for correctness. Knowing that is the interesting part.

### Phase 8 — Presentation (1–2 days)
README that leads with the bypass finding. Honest coverage table with a mode column. Threat model with MITRE ATT&CK mapping and an explicit "what WAF cannot do" section. Runbooks for three incidents. Diagrams as code rendered in CI. Cost model. Evidence bundle committed. A short recorded walkthrough: deploy → attack → detect → destroy.

**Total: roughly 15–20 working days.** Phases 0–4 alone (about 9 days) already produce something markedly stronger than v1 — if you need to ship sooner, stop after Phase 5 and add the rest later.

---

## 14. Questions you should be able to answer cold

Rehearse these. They are what you will actually be asked.

1. **Why does a Web ACL scoped to CloudFront have to live in us-east-1?**
2. **What happens when a request matches a rule with a terminating `Allow`?** (This is the v1 bug — own it.)
3. **Why is OAC better than OAI, and what does the `AWS:SourceArn` condition prevent?**
4. **Your WAF blocks a legitimate customer at 2am. Walk me through it.** (Your runbook should already answer this.)
5. **Why did you run managed rules in COUNT before BLOCK, and how did you decide the exclusions?**
6. **Why OIDC instead of an access key in GitHub secrets?**
7. **What can't a WAF do?** (Business logic abuse, authenticated account takeover, anything in encrypted request bodies it can't inspect, anything past the body inspection size limit, attacks that reach the origin directly.)
8. **What's a WCU and why should you care?**
9. **How would this change with real production traffic?** (Canary rule deployment, longer count windows, sampling, rollback plan.)
10. **What would you do differently if you built it again?** (Have a real answer ready — it's the question people fail on.)

---

## 15. Open decisions

Things this plan assumes. Flag any you want to change before we start writing HCL.

| # | Decision | Assumed | Alternative |
|---|----------|---------|-------------|
| 1 | IaC tool | Terraform (HashiCorp) | OpenTofu — near-identical HCL, mention it if you prefer |
| 2 | Terraform version | ≥ 1.11, for S3 native state locking | ≥ 1.6 with a DynamoDB lock table |
| 3 | Region | `us-east-1` for both envs | dev could be closer to you for latency; prod's WAF must be us-east-1 regardless |
| 4 | AWS accounts | Single account | Two accounts is more realistic but adds Organizations setup and cost |
| 5 | Dev origin | ALB with fixed-response listener | API Gateway (no VPC needed at all, but a different WAF integration) |
| 6 | Module testing | Native `terraform test` (`.tftest.hcl`) | Terratest — more powerful, needs Go |
| 7 | Custom domain | None; use the CloudFront/ALB default names | Route53 + ACM is ~$0.50/month for the hosted zone and makes HSTS meaningful |
| 8 | Python CLI framework | `typer` + `rich` | `click`, or plain `argparse` |
| 9 | Auto-remediation | Phase 7, optional | Cut it if you want to ship in 2 weeks |
| 10 | Repo name | `waf-ops-platform` | Your call — pick something that isn't "-suite" so it reads as distinct from v1 |

---

## Sources

- [AWS WAF Pricing](https://aws.amazon.com/waf/pricing) — $5/Web ACL/month, $1/rule/month, $1/managed rule group/month, all prorated hourly; $0.60 per million requests; Bot Control $10/Web ACL/month.
- [Elastic Load Balancing Pricing](https://aws.amazon.com/elasticloadbalancing/pricing/) — ALB $0.0225/hour and $0.008/LCU-hour in US East (N. Virginia).
- [Akash-Bhavsar/WAF-Ops-Suite](https://github.com/Akash-Bhavsar/WAF-Ops-Suite) — the v1 prototype this plan replaces.
