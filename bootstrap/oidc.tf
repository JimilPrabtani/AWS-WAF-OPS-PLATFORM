# ---------------------------------------------------------------------------
# GitHub OIDC federation.
#
# This replaces "put an AWS access key in GitHub secrets".
#
# What actually happens: a workflow run asks GitHub for a signed JWT describing
# itself -- repository, branch or environment, workflow, actor. It presents that
# token to AWS STS. STS validates the signature against GitHub's published keys
# and checks the token's claims against the role's trust policy. If they match,
# STS issues short-lived credentials.
#
# The consequences are what matter in an interview:
#   - Nothing long-lived exists to leak. There is no secret in the repo, in
#     GitHub, on a laptop, or in a screenshot.
#   - The trust policy is scoped to ONE repository and ONE ref/environment.
#     A fork, another repo, or another branch cannot assume these roles.
#   - Revocation is deleting a role, not rotating a key everywhere it was used.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  # AWS validates GitHub's certificate against its own trust store and no longer
  # uses this value for this provider. It is kept because some provider versions
  # still require the argument to be present.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

locals {
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_audience     = "sts.amazonaws.com"

  # Subjects the PLAN role accepts. Pull requests are included on purpose: a
  # contributor should be able to see a plan. They cannot reach the apply role.
  plan_subjects = [
    "repo:${var.github_repository}:pull_request",
    "repo:${var.github_repository}:ref:refs/heads/main",
  ]

  # Subjects the APPLY role accepts. `environment:` subjects are only issued
  # after GitHub's environment protection rules are satisfied -- which is where
  # the required human approval lives. A pull_request token can never match.
  apply_subjects = [
    "repo:${var.github_repository}:environment:dev",
    "repo:${var.github_repository}:environment:prod",
  ]
}

# ---------------------------------------------------------------------------
# Plan role -- read-only, plus the state access a plan needs
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "plan_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = [local.oidc_audience]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.plan_subjects
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = "WAFOpsPlanRole"
  description          = "Read-only role assumed by CI to produce Terraform plans"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

# A plan reads the world, so ReadOnlyAccess is genuinely the right scope here --
# it grants no mutation. Scoping it further buys nothing and breaks constantly
# as the module grows.
resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# A plan must still write the .tflock object, so state access is read/write on
# the lock and read on the state itself.
data "aws_iam_policy_document" "state_access" {
  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketVersioning"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.state.arn}/*"]
  }
}

resource "aws_iam_policy" "state_access" {
  name        = "WAFOpsStateAccess"
  description = "Terraform state bucket access, including the native S3 lock object"
  policy      = data.aws_iam_policy_document.state_access.json
}

resource "aws_iam_role_policy_attachment" "plan_state" {
  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.state_access.arn
}

# ---------------------------------------------------------------------------
# Apply role -- write, gated behind a GitHub environment approval
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "apply_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = [local.oidc_audience]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.apply_subjects
    }
  }
}

resource "aws_iam_role" "apply" {
  name                 = "WAFOpsApplyRole"
  description          = "Write role assumed by CI after a human approves the environment"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "apply_state" {
  role       = aws_iam_role.apply.name
  policy_arn = aws_iam_policy.state_access.arn
}

resource "aws_iam_role_policy_attachment" "apply_deploy" {
  role       = aws_iam_role.apply.name
  policy_arn = aws_iam_policy.deploy.arn
}

# ---------------------------------------------------------------------------
# Human deploy role -- what you assume locally instead of using your own keys
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "human_trust" {
  count = length(var.human_principal_arns) > 0 ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.human_principal_arns
    }

    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "human" {
  count = length(var.human_principal_arns) > 0 ? 1 : 0

  name                 = "WAFOpsDeployRole"
  description          = "Assumed from the CLI for local development. MFA required by default."
  assume_role_policy   = data.aws_iam_policy_document.human_trust[0].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "human_state" {
  count = length(var.human_principal_arns) > 0 ? 1 : 0

  role       = aws_iam_role.human[0].name
  policy_arn = aws_iam_policy.state_access.arn
}

resource "aws_iam_role_policy_attachment" "human_deploy" {
  count = length(var.human_principal_arns) > 0 ? 1 : 0

  role       = aws_iam_role.human[0].name
  policy_arn = aws_iam_policy.deploy.arn
}
