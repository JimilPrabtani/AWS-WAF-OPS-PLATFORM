# Bootstrap — run this once

Creates the things every other configuration depends on: the Terraform state
bucket, the GitHub OIDC provider, and the three IAM roles.

**This configuration uses local state**, because it creates the bucket the others
store their state in. `terraform.tfstate` here is gitignored. If you lose it,
import the resources rather than re-creating them — the bucket has
`prevent_destroy` set for exactly that reason.

## Steps

```bash
cp terraform.tfvars.example terraform.tfvars
# fill in: state_bucket_name, github_repository, human_principal_arns

terraform init
terraform apply
```

## Then

**1. Wire up your local profile.**

```bash
terraform output aws_config_snippet
```

Paste into `~/.aws/config`, replace `<YOUR_MFA_DEVICE_NAME>`, then:

```bash
export AWS_PROFILE=wafops-deploy
aws sts get-caller-identity     # should show WAFOpsDeployRole
```

**2. Point the environments at the state bucket.** Edit
`envs/dev/backend.tf` and `envs/prod/backend.tf`, replacing
`REPLACE_ME_STATE_BUCKET`. Backend blocks cannot take variables — that is a
Terraform limitation, not an oversight.

**3. Set the CI variables.** In the GitHub repository, under
*Settings → Secrets and variables → Actions → Variables*:

| Variable | Value |
|---|---|
| `AWS_PLAN_ROLE` | `terraform output -raw plan_role_arn` |
| `AWS_APPLY_ROLE` | `terraform output -raw apply_role_arn` |

These are **variables, not secrets** — role ARNs are not sensitive, and nothing
here is. That is the point of OIDC.

**4. Create the GitHub Environments.** Under *Settings → Environments*, create
`dev` and `prod`, and add yourself as a required reviewer on `prod`.

This is what makes the apply role safe: GitHub only mints a token with an
`environment:` subject after those protection rules pass, and the apply role's
trust policy accepts nothing else.

## Troubleshooting

**`EntityAlreadyExists` on the OIDC provider** — you already have one for GitHub
in this account. Import it:

```bash
terraform import aws_iam_openid_connect_provider.github \
  arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com
```

**`AccessDenied` when assuming the deploy role** — check that your IAM user has an
MFA device and that you are using the profile, not raw keys. Set
`require_mfa = false` temporarily if you have not set up MFA yet, then turn it
back on.
