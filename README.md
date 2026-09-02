# WAF Ops Platform

A production-shaped AWS WAF deployment defined entirely in Terraform, attachable
to either a regional ALB or a CloudFront distribution from the same module, with
rule modes driven by logged evidence rather than assertion, deployed by a
least-privilege role over GitHub OIDC with no stored credentials, and costing
about a cent a month at rest.

> **Status:** infrastructure and tooling complete; rule tuning in progress.
> Two rules are still in COUNT mode on purpose — see [Coverage](#coverage).

---

## Why this exists

This project began as an audit of an existing Python/boto3 WAF prototype
([WAF-Ops-Suite](https://github.com/Akash-Bhavsar/WAF-Ops-Suite), MIT). The audit
found a defect that invalidated the prototype's central claim, plus several
smaller ones. This is the rebuild.

**The finding: the WAF could be bypassed completely.** The deployment script
disabled all four S3 Block Public Access settings, attached a bucket policy
granting `s3:GetObject` to `Principal: "*"`, enabled S3 static website hosting,
and pointed CloudFront at the origin with an empty `OriginAccessIdentity`. The
bucket was therefore readable at its own S3 URL — anyone who found it served the
same site with zero WAF rules in front of it.

Full write-up: [`docs/FINDINGS-FROM-V1.md`](docs/FINDINGS-FROM-V1.md).

| | Prototype | This |
|---|---|---|
| Origin | Public bucket, no OAC/OAI | Private bucket, OAC, `aws:SourceArn` pinned to the distribution |
| Trusted IPs | Terminating `Allow` at priority 0 — disabled every later rule | `NotStatement` scope-down inside individual rules |
| CSRF | Blocked requests missing a header WAF never validated | Origin/Referer validation, with the limits documented |
| Request logging | None. Detection ran on sampled data | CloudWatch Logs, redacted headers, versioned detections |
| Alarms | `ActionsEnabled = false`, no topic | Wired to SNS end to end |
| State | Gitignored local JSON | S3 backend, versioned, native locking |
| Credentials | `aws configure`, `AdministratorAccess` | Assumed role locally; GitHub OIDC in CI, nothing stored |
| Tests | 3 live suites; transport errors counted as passes | Offline unit tests, module contract tests, plan policies, live E2E |
| Failure handling | Scripts exited 0 on failure | `terraform` exit codes; CI gates |

---

## Architecture

```
             ┌──────── prod ── CLOUDFRONT scope, us-east-1 ──────────────────┐
             │ CloudFront ──► Web ACL ──┬► S3 origin (private, OAC): wandor  │
Internet ──► │                          └► /api/* ► API GW ► Lambda          │
             └──────────────────────┬────────────────────┬───────────────────┘
                                    │                    │
             ┌──────── dev ── REGIONAL scope ──────────┐ │  ┌─ data (persistent, ~$0/mo) ─┐
Internet ──► │ ALB ───► Web ACL ──► fixed-response     │ │  │ Cognito · DynamoDB ·        │
             └──────────────────────┬──────────────────┘ └─►│ Secrets Manager · RUM       │
                                    ▼                       └─────────────────────────────┘
                    CloudWatch Logs (aws-waf-logs-*)        ┌─ security (always-on) ──────┐
                    ├── Logs Insights ← detections/*.yaml   │ CloudTrail · Config ·       │
                    ├── metric filters → alarms → SNS       │ Security Hub CSPM · Guard-  │
                    └── dashboard                           │ Duty · Access Analyzer ·    │
                                                            │ findings→email · Budget     │
                                                            └─────────────────────────────┘
```

The protected application is **wandor** (sibling repo/folder): a React SPA served
from the private S3 origin, with a serverless API (Cognito JWT auth, Gemini →
OpenRouter failover for AI itineraries, DynamoDB persistence) reachable only
through CloudFront — the Lambda rejects requests that skipped the WAF by
checking a CloudFront-injected `x-origin-verify` header. State is split so
`terraform destroy` on prod never deletes users or their data: `envs/data` and
`envs/security` stay up (both ~free at rest); `envs/prod` and `envs/dev` remain
deploy-and-destroy.

The dev environment's ALB listener answers from a `fixed-response` action — no
target group, no EC2, no containers. It exists because a CloudFront distribution
takes 15–20 minutes to deploy and about the same to tear down, so tuning a rule
against CloudFront costs a 40-minute round trip. The ALB comes up in about 90
seconds. Rules are developed in dev and promoted to prod.

---

## Coverage

Modes are stated honestly. A COUNT rule blocks nothing and is not claimed as
coverage.

| Pri | Rule | dev | prod | Notes |
|----:|------|-----|------|-------|
| 10 | BlockedIPs | BLOCK | BLOCK | Populated deliberately; auto-remediation entries carry a TTL |
| 20 | RateLimit | COUNT | **BLOCK** | prod: 300 req / 5 min, scoped to `/api/`, `/login`, `/search` |
| 30 | AWSCommonRuleSet | COUNT | COUNT | *Not yet promoted — awaiting tuning data* |
| 40 | AWSKnownBadInputs | BLOCK | **BLOCK** | Log4Shell, SSRF, traversal. Best value per WCU |
| 50 | AWSAnonymousIpList | COUNT | COUNT | Permanently counted — blocking every VPN user is a real cost |
| 60 | GeoRestriction | COUNT | **BLOCK** | Noise reduction, *not* a security boundary. Any VPN defeats it |
| 70 | OriginValidation | COUNT | **BLOCK** | Replaces the prototype's CSRF rule |
| 80 | SuspiciousUserAgents | COUNT | COUNT | Permanently counted — one `curl -A` flag defeats it |

### What this does not do

- Not DDoS protection. That is Shield Advanced.
- Not bot management. That is Bot Control, and it bills per request.
- Not CSRF protection. WAF has no session state; real CSRF defence is SameSite
  cookies plus server-side token validation.
- Has never seen production traffic. All measurements come from synthetic
  traffic generated by `wafops`.

---

## Quick start

```bash
# 1. One-time bootstrap: state bucket, OIDC provider, roles
cd bootstrap
cp terraform.tfvars.example terraform.tfvars   # fill in
terraform init && terraform apply
terraform output aws_config_snippet            # paste into ~/.aws/config

# 2. Point the environments at the state bucket
#    (edit envs/*/backend.tf — backend blocks cannot take variables)

# 3. Bring dev up
export AWS_PROFILE=wafops-deploy
cd ../envs/dev
cp terraform.tfvars.example terraform.tfvars   # add your public IP
terraform init && terraform apply

# 4. Test it
pip install -e ../../wafops
wafops attack run   --env dev
wafops falsepos run --env dev

# 5. Tear it down. Every time.
terraform destroy
```

### Deploying the application (prod)

```bash
# One-time, in order:
terraform -chdir=envs/security init && terraform -chdir=envs/security apply  # account baseline, stays up
terraform -chdir=envs/data init && terraform -chdir=envs/data apply          # users/data/keys, stays up
aws secretsmanager put-secret-value --secret-id wandor/ai-keys \
  --secret-string '{"gemini":"...","openrouter":"..."}'                      # never in Terraform state

# Every prod cycle:
cd ../wandor && cp .env.example .env      # fill VITE_* from `terraform -chdir=envs/data output`
npm ci && npm run build                   # dist/ is what prod uploads
cd ../waf-ops-platform/envs/prod
cp terraform.tfvars.example terraform.tfvars
terraform init && terraform apply         # ~15-20 min (CloudFront)
terraform output callback_url_for_data_env   # add to envs/data tfvars, re-apply data (seconds)
# ...and add the new CloudFront domain to the Google OAuth client's authorized origins.

wafops attack run --env prod && wafops falsepos run --env prod && wafops verify bypass --env prod
terraform destroy                          # prod only; data and security stay
```

With `make`: `make ENV=dev apply attack falsepos destroy`.
Everything that runs without AWS credentials: `make check`.

---

## Cost

Verified against AWS pricing (us-east-1). Web ACL and rule charges are prorated
hourly, which is what makes deploy-and-destroy viable.

| | Rate |
|---|---|
| dev while running | **~$0.042 / hour** (ALB $0.0225 + ACL $0.0068 + 8 rules $0.0110) |
| prod while running | **~$0.019 / hour** (CloudFront within free tier; Lambda/API GW/DynamoDB in free tiers at this traffic) |
| At rest, destroyed | **~$0.41 / month** (state bucket + the AI-keys secret; Cognito/DynamoDB/RUM idle at $0) |
| Security baseline (always-on, accepted) | **~$0 for 30 days**, then a few $/month (Config + Security Hub + GuardDuty) |
| Full validation cycle | **under $1** (plus AI provider usage) |

`.github/workflows/drift.yml` runs daily and fails if anything is still up —
the budget posture is enforced, not just claimed. Details in
[`docs/COST-MODEL.md`](docs/COST-MODEL.md).

---

## Repository map

| Path | What's in it |
|---|---|
| `bootstrap/` | State bucket, GitHub OIDC provider, plan/apply/human roles, deploy policies, wandor's site-deploy role. Run once |
| `modules/waf/` | The core module. Dual scope, rules as typed data, logging, IP sets |
| `modules/static-site/` | Private S3 + CloudFront + OAC serving any build directory, SPA fallback, optional /api origin. The bypass fix lives here |
| `modules/api/` | wandor's backend: Lambda + HTTP API, Cognito JWT auth, AI failover, free-plan cap, OWASP-LLM hardening |
| `modules/alb-target/` | Fixed-response ALB. The fast dev target |
| `modules/observability/` | Dashboard, SNS, alarms (WAF + API), detection metric filters |
| `envs/dev`, `envs/prod` | Thin roots. Same rules, different modes — `diff` them |
| `envs/data` | PERSISTENT app layer: Cognito, DynamoDB, AI-keys secret, RUM. Never in the destroy cycle |
| `envs/security` | Always-on account baseline: CloudTrail, Config, Security Hub CSPM, GuardDuty, Access Analyzer, budget alert |
| `../wandor` | The protected application (React SPA + its deploy workflow) |
| `policies/conftest/` | Custom OPA policies encoding this project's own defects |
| `detections/` | Detection-as-code: query, threshold, rationale, false positives |
| `wafops/` | Python CLI: attack suite, benign suite, bypass check, evidence bundle |
| `docs/` | Plan, code walkthrough, threat model, tuning report, runbooks |

Start with [`docs/CODE-WALKTHROUGH.md`](docs/CODE-WALKTHROUGH.md).

---

## Credits

Started from a Python/boto3 prototype by
[Akash Bhavsar](https://github.com/Akash-Bhavsar/WAF-Ops-Suite), MIT licensed.
The attack payload catalog and the false-positive testing approach are derived
from that project; the infrastructure, security model and tooling are a rewrite.

## License

MIT — see [LICENSE](LICENSE).
