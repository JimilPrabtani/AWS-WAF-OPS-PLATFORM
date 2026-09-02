# ---------------------------------------------------------------------------
# wandor API: one Lambda behind an HTTP API with a Cognito JWT authorizer.
#
# This API is only reachable two ways, and both are enforced:
#   1. A valid Cognito JWT -- checked by API Gateway before the Lambda runs.
#   2. Through CloudFront -- proven by the x-origin-verify header the
#      distribution injects; the Lambda refuses requests without it, so the
#      direct execute-api URL cannot be used to skip the WAF. Same class of
#      defect as the public-bucket bypass this project was built around.
# ---------------------------------------------------------------------------

data "aws_region" "current" {}

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/src/handler.mjs"
  output_path = "${path.module}/.build/handler.zip"
}

# --- IAM: the Lambda can touch ONE table and read ONE secret ---------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "TableScoped"
    actions = [
      "dynamodb:Query",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
      "dynamodb:UpdateItem",
    ]
    resources = [var.table_arn]
  }

  statement {
    sid       = "SecretScoped"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.ai_keys_secret_arn]
  }

  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.name}-api-lambda"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "lambda" {
  name   = "least-privilege"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

# --- Lambda ----------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name}-api"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_lambda_function" "api" {
  function_name = "${var.name}-api"
  role          = aws_iam_role.lambda.arn

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "nodejs22.x"
  architectures    = ["arm64"]
  memory_size      = 256
  timeout          = 28 # under API Gateway's ~30s integration ceiling

  environment {
    variables = {
      TABLE_NAME         = var.table_name
      AI_KEYS_SECRET_ARN = var.ai_keys_secret_arn
      ORIGIN_VERIFY      = var.origin_verify_secret
      GEMINI_MODEL       = var.gemini_model
      OPENROUTER_MODEL   = var.openrouter_model
      TRIP_LIMIT         = tostring(var.trip_limit)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
  tags       = var.tags
}

# --- HTTP API with JWT auth ------------------------------------------------

resource "aws_apigatewayv2_api" "api" {
  name          = "${var.name}-api"
  protocol_type = "HTTP"
  tags          = var.tags
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.api.id
  name             = "cognito-jwt"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    issuer   = "https://cognito-idp.${data.aws_region.current.region}.amazonaws.com/${var.user_pool_id}"
    audience = [var.user_pool_client_id]
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "routes" {
  for_each = toset([
    "POST /api/trips/generate",
    "GET /api/trips",
    "DELETE /api/trips/{id}",
  ])

  api_id             = aws_apigatewayv2_api.api.id
  route_key          = each.value
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = 20
    throttling_burst_limit = 40
  }

  tags = var.tags
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}
