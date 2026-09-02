# ---------------------------------------------------------------------------
# Deploy role for the wandor FRONTEND repo.
#
# Same OIDC provider, different repository, far smaller blast radius: this
# role can only write objects into the prod origin bucket and invalidate the
# CloudFront cache. It cannot touch Terraform state, the WAF, or any other
# infrastructure -- pushing frontend code is not an infrastructure change.
# ---------------------------------------------------------------------------

variable "wandor_repository" {
  description = "GitHub repository (owner/name) of the wandor frontend. Null skips creating its deploy role."
  type        = string
  default     = null
}

data "aws_iam_policy_document" "wandor_trust" {
  count = var.wandor_repository == null ? 0 : 1

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
      values   = ["repo:${var.wandor_repository}:ref:refs/heads/main"]
    }
  }
}

data "aws_iam_policy_document" "wandor_deploy" {
  count = var.wandor_repository == null ? 0 : 1

  statement {
    sid    = "SyncSiteBucket"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::wafops-prod-origin-${data.aws_caller_identity.current.account_id}",
      "arn:aws:s3:::wafops-prod-origin-${data.aws_caller_identity.current.account_id}/*",
    ]
  }

  statement {
    sid       = "InvalidateCache"
    effect    = "Allow"
    actions   = ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"]
    resources = ["*"] # CreateInvalidation is not resource-scopable before the distribution exists
  }
}

resource "aws_iam_role" "wandor_deploy" {
  count = var.wandor_repository == null ? 0 : 1

  name                 = "WandorSiteDeployRole"
  description          = "Assumed by the wandor repo's GitHub Actions to sync dist/ and invalidate CloudFront."
  assume_role_policy   = data.aws_iam_policy_document.wandor_trust[0].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "wandor_deploy" {
  count = var.wandor_repository == null ? 0 : 1

  name   = "site-sync-only"
  role   = aws_iam_role.wandor_deploy[0].id
  policy = data.aws_iam_policy_document.wandor_deploy[0].json
}

output "wandor_deploy_role_arn" {
  value = var.wandor_repository == null ? null : aws_iam_role.wandor_deploy[0].arn
}
