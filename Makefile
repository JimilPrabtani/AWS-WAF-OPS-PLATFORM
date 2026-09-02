# WAF Ops Platform
#
# On Windows use WSL, Git Bash, or run the underlying commands directly --
# every target here is a one-line wrapper and the README lists the raw form.

ENV     ?= dev
CHDIR    = -chdir=envs/$(ENV)
TF      ?= terraform

.DEFAULT_GOAL := help
.PHONY: help init fmt validate lint policy test plan apply deploy destroy attack falsepos verify evidence cost check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

init: ## terraform init for $(ENV)
	$(TF) $(CHDIR) init

fmt: ## Rewrite all HCL to canonical format
	$(TF) fmt -recursive

validate: ## terraform validate for $(ENV)
	$(TF) $(CHDIR) validate

lint: ## tflint across modules and envs
	tflint --recursive

test: ## Native module tests (no infrastructure created)
	$(TF) -chdir=modules/waf test -verbose

policy: ## Checkov + custom Conftest policies against a plan
	$(TF) $(CHDIR) plan -out=tfplan
	$(TF) $(CHDIR) show -json tfplan > tfplan.json
	checkov -f tfplan.json --framework terraform_plan --quiet
	conftest test --policy policies/conftest tfplan.json

check: fmt validate lint test ## Everything that runs without AWS credentials

plan: ## Show what would change in $(ENV)
	$(TF) $(CHDIR) plan

apply: ## Apply $(ENV)
	$(TF) $(CHDIR) apply

deploy: apply ## Alias for apply

destroy: ## Tear $(ENV) down. Run this. Every time.
	$(TF) $(CHDIR) destroy

attack: ## Run the attack vector suite against $(ENV)
	wafops attack run --env $(ENV)

falsepos: ## Run the legitimate-traffic suite against $(ENV)
	wafops falsepos run --env $(ENV)

verify: ## Assert the origin cannot be reached directly (prod only)
	wafops verify bypass --env $(ENV)

evidence: ## Produce the evidence bundle for docs/evidence/
	wafops report generate --env $(ENV)

cost: ## Estimated cost of the current plan
	infracost breakdown --path envs/$(ENV)
