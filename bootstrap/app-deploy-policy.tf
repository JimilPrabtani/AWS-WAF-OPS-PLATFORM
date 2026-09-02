# ---------------------------------------------------------------------------
# Application deploy policy.
#
# Added when the platform gained a real application to protect (wandor):
# Cognito, DynamoDB, Secrets Manager, Lambda, API Gateway, RUM, and the
# envs/security account baseline. A separate managed policy on the same roles
# as WAFOpsDeployPolicy because one document hits IAM's 6144-character cap.
#
# The explicit deny in deploy-policy.tf still applies across both policies --
# denies win over any allow regardless of which attached policy grants it.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "app_deploy" {

  # Cognito has partial resource-level support; user pool ARNs are not known
  # before creation, so these are account-scoped like CloudFront.
  statement {
    sid    = "CognitoManage"
    effect = "Allow"
    actions = [
      "cognito-idp:*",
      "cognito-identity:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DynamoDBAppTables"
    effect = "Allow"
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:DeleteTable",
      "dynamodb:DescribeTable",
      "dynamodb:UpdateTable",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:UpdateContinuousBackups",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:ListTagsOfResource",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
    ]
    resources = ["arn:aws:dynamodb:*:*:table/wandor-*"]
  }

  # Deploy manages the secret CONTAINER only. GetSecretValue is deliberately
  # absent: values are set by a human and read by the Lambda role, never by
  # this role.
  statement {
    sid    = "SecretsManagerAppSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:UpdateSecret",
      "secretsmanager:TagResource",
      "secretsmanager:UntagResource",
      "secretsmanager:GetResourcePolicy",
    ]
    resources = ["arn:aws:secretsmanager:*:*:secret:wandor/*"]
  }

  statement {
    sid     = "LambdaAppFunctions"
    effect  = "Allow"
    actions = ["lambda:*"]
    resources = [
      "arn:aws:lambda:*:*:function:wafops-*",
      "arn:aws:lambda:*:*:function:wandor-*",
    ]
  }

  # API Gateway uses its own ARN format with generated ids; not scopable
  # before creation.
  statement {
    sid       = "ApiGatewayManage"
    effect    = "Allow"
    actions   = ["apigateway:*"]
    resources = ["*"]
  }

  statement {
    sid       = "RumManage"
    effect    = "Allow"
    actions   = ["rum:*"]
    resources = ["*"]
  }

  # IAM role management is allowed ONLY for lowercase application role name
  # prefixes. The platform's own roles are WAFOps* (capitalized) and IAM ARNs
  # are case-sensitive, so this role cannot modify the roles it runs as --
  # that separation is what makes granting any iam: action tolerable at all.
  statement {
    sid    = "IamAppRolesOnly"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = [
      "arn:aws:iam::*:role/wafops-*",
      "arn:aws:iam::*:role/wandor-*",
    ]
  }

  # PassRole is the escalation primitive, so it is pinned twice: to the app
  # role prefixes AND to the services allowed to receive them.
  statement {
    sid     = "PassAppRolesToServices"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::*:role/wafops-*",
      "arn:aws:iam::*:role/wandor-*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com", "cognito-identity.amazonaws.com"]
    }
  }

  # envs/security baseline: account-level services whose setup calls have no
  # meaningful resource-level scoping.
  statement {
    sid    = "SecurityBaseline"
    effect = "Allow"
    actions = [
      "cloudtrail:*",
      "config:*",
      "securityhub:*",
      "access-analyzer:*",
      "guardduty:*",
      "events:*",
      "budgets:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ConfigServiceLinkedRole"
    effect = "Allow"
    actions = [
      "iam:CreateServiceLinkedRole",
      "iam:DeleteServiceLinkedRole",
      "iam:GetServiceLinkedRoleDeletionStatus",
    ]
    resources = ["arn:aws:iam::*:role/aws-service-role/config.amazonaws.com/*"]
  }
}

resource "aws_iam_policy" "app_deploy" {
  name        = "WAFOpsAppDeployPolicy"
  description = "Application (wandor) and security-baseline permissions for the deploy roles"
  policy      = data.aws_iam_policy_document.app_deploy.json
}

resource "aws_iam_role_policy_attachment" "apply_app_deploy" {
  role       = aws_iam_role.apply.name
  policy_arn = aws_iam_policy.app_deploy.arn
}

resource "aws_iam_role_policy_attachment" "human_app_deploy" {
  count = length(var.human_principal_arns) > 0 ? 1 : 0

  role       = aws_iam_role.human[0].name
  policy_arn = aws_iam_policy.app_deploy.arn
}
