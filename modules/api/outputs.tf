output "api_endpoint" {
  description = "Invoke URL of the HTTP API."
  value       = aws_apigatewayv2_api.api.api_endpoint
}

output "api_origin_domain" {
  description = "Bare hostname for use as a CloudFront origin."
  value       = replace(aws_apigatewayv2_api.api.api_endpoint, "https://", "")
}

output "lambda_function_name" {
  value = aws_lambda_function.api.function_name
}

output "lambda_log_group_name" {
  value = aws_cloudwatch_log_group.lambda.name
}

output "api_id" {
  value = aws_apigatewayv2_api.api.id
}
