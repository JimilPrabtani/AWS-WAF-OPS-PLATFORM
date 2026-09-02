output "user_pool_id" {
  value = aws_cognito_user_pool.users.id
}

output "user_pool_arn" {
  value = aws_cognito_user_pool.users.arn
}

output "user_pool_client_id" {
  value = aws_cognito_user_pool_client.spa.id
}

output "cognito_domain" {
  description = "Hosted-UI domain used for federated sign-in redirects."
  value       = "${aws_cognito_user_pool_domain.users.domain}.auth.${var.region}.amazoncognito.com"
}

output "table_name" {
  value = aws_dynamodb_table.trips.name
}

output "table_arn" {
  value = aws_dynamodb_table.trips.arn
}

output "ai_keys_secret_arn" {
  value = aws_secretsmanager_secret.ai_keys.arn
}

output "rum_app_monitor_id" {
  value = aws_rum_app_monitor.spa.app_monitor_id
}

output "rum_identity_pool_id" {
  value = aws_cognito_identity_pool.rum.id
}

output "rum_guest_role_arn" {
  value = aws_iam_role.rum_guest.arn
}

output "google_idp_enabled" {
  # A yes/no flag reveals nothing about the secret itself.
  value = nonsensitive(var.google_client_secret != null)
}
