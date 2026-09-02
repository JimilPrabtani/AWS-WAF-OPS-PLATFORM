# ---------------------------------------------------------------------------
# The deploy policy.
#
# This file replaces the prototype's advice to "just use AdministratorAccess".
#
# Read the comments: the interesting part is not that it is scoped, it is WHERE
# it cannot be. Several AWS services do not support resource-level permissions
# for the actions Terraform needs, so those statements are necessarily "*".
# Saying which ones and why is a much better answer than pretending the whole
# policy is tight.
#
# Expect to iterate. Run an apply, hit AccessDenied, add the one action, commit.
# Keep those commits -- the history of narrowing a policy is itself the evidence
# that you did the work.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "deploy" {

  # WAFv2 supports resource-level permissions, but Terraform must also call
  # List* and the CheckCapacity API, which are account-scoped.
  statement {
    sid    = "WAFv2Manage"
    effect = "Allow"
    actions = [
      "wafv2:*",
    ]
    resources = ["*"]
  }

  # CloudFront does NOT support resource-level permissions for most actions --
  # CreateDistribution has no ARN to scope to because the ARN does not exist
  # until the call succeeds. This statement is wildcard because AWS gives no
  # alternative, not because scoping was skipped.
  statement {
    sid    = "CloudFrontManage"
    effect = "Allow"
    actions = [
      "cloudfront:CreateDistribution",
      "cloudfront:UpdateDistribution",
      "cloudfront:DeleteDistribution",
      "cloudfront:GetDistribution",
      "cloudfront:GetDistributionConfig",
      "cloudfront:ListDistributions",
      "cloudfront:TagResource",
      "cloudfront:UntagResource",
      "cloudfront:ListTagsForResource",
      "cloudfront:CreateOriginAccessControl",
      "cloudfront:GetOriginAccessControl",
      "cloudfront:GetOriginAccessControlConfig",
      "cloudfront:UpdateOriginAccessControl",
      "cloudfront:DeleteOriginAccessControl",
      "cloudfront:ListOriginAccessControls",
      "cloudfront:CreateResponseHeadersPolicy",
      "cloudfront:GetResponseHeadersPolicy",
      "cloudfront:GetResponseHeadersPolicyConfig",
      "cloudfront:UpdateResponseHeadersPolicy",
      "cloudfront:DeleteResponseHeadersPolicy",
      "cloudfront:ListResponseHeadersPolicies",
      "cloudfront:ListCachePolicies",
      "cloudfront:GetCachePolicy",
      "cloudfront:CreateInvalidation",
    ]
    resources = ["*"]
  }

  # S3 IS scopable, so it is scoped: only buckets named for this project.
  statement {
    sid    = "S3ProjectBuckets"
    effect = "Allow"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:ListBucket",
      "s3:GetBucket*",
      "s3:PutBucket*",
      "s3:DeleteBucketPolicy",
      "s3:GetObject*",
      "s3:PutObject*",
      "s3:DeleteObject*",
      "s3:GetEncryptionConfiguration",
      "s3:PutEncryptionConfiguration",
      "s3:GetAccountPublicAccessBlock",
    ]
    resources = [
      "arn:aws:s3:::wafops-*",
      "arn:aws:s3:::wafops-*/*",
    ]
  }

  # ELB has no resource-level permission for CreateLoadBalancer either.
  statement {
    sid    = "LoadBalancerManage"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:*",
    ]
    resources = ["*"]
  }

  # EC2 is read-only apart from security groups, which the ALB requires.
  # Note the absence of ec2:RunInstances -- this role cannot start compute.
  statement {
    sid    = "NetworkingReadAndSecurityGroups"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:CreateTags",
      "ec2:DeleteTags",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ObservabilityManage"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:DescribeLogGroups",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:ListTagsForResource",
      "logs:PutResourcePolicy",
      "logs:DeleteResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:PutMetricFilter",
      "logs:DeleteMetricFilter",
      "logs:DescribeMetricFilters",
      "logs:StartQuery",
      "logs:GetQueryResults",
      "logs:FilterLogEvents",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListTagsForResource",
      "cloudwatch:TagResource",
      "cloudwatch:UntagResource",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:PutDashboard",
      "cloudwatch:DeleteDashboards",
      "cloudwatch:GetDashboard",
      "cloudwatch:ListDashboards",
      "sns:CreateTopic",
      "sns:DeleteTopic",
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:Subscribe",
      "sns:Unsubscribe",
      "sns:ListSubscriptionsByTopic",
      "sns:TagResource",
      "sns:UntagResource",
      "sns:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "Identity"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }

  # Application (wandor) and security-baseline statements live in
  # app-deploy-policy.tf -- a second managed policy on the same roles, split
  # because a single policy document bumps into IAM's 6144-character limit.

  # An explicit deny is a belt-and-braces guard: even if a future statement is
  # written too broadly, this role can never mint credentials, touch users, or
  # start compute. Explicit denies win over any allow in IAM evaluation.
  # (iam:* and guardduty:* left this list when the application landed; role
  # management is now allowed but ONLY on the lowercase app prefixes above,
  # and everything user- and credential-shaped stays denied.)
  statement {
    sid    = "NeverUsersCredsOrCompute"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:DeleteUser",
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:AttachUserPolicy",
      "iam:PutUserPolicy",
      "iam:AddUserToGroup",
      "iam:CreateGroup",
      "iam:AttachRolePolicy", # app roles get inline policies; attaching managed ones (e.g. AdministratorAccess) stays impossible
      "organizations:*",
      "ec2:RunInstances",
      "ec2:TerminateInstances",
      "shield:*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "deploy" {
  name        = "WAFOpsDeployPolicy"
  description = "Least-privilege policy for deploying the WAF Ops Platform"
  policy      = data.aws_iam_policy_document.deploy.json
}
