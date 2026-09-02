# ---------------------------------------------------------------------------
# data: the application's PERSISTENT layer.
#
# Everything here costs ~$0 at rest (the secret is $0.40/month) and survives
# the deploy-and-destroy cycle of envs/prod. Destroying this root deletes user
# accounts and their trips -- which is why the table carries deletion
# protection and nothing in the Makefile ever destroys it.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# --- Identity -------------------------------------------------------------

resource "aws_cognito_user_pool" "users" {
  name = "${var.name}-users"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # Cognito's built-in sender: fine for a demo, capped at ~50 emails/day.
  # ponytail: switch email_configuration to SES if signup volume ever matters.
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  deletion_protection = "ACTIVE"
  tags                = var.tags
}

# Hosted UI domain -- only used for the federated (Google) redirect flow; the
# email/password UI stays wandor's own pages via the SRP SDK.
resource "aws_cognito_user_pool_domain" "users" {
  domain       = "${var.name}-${data.aws_caller_identity.current.account_id}"
  user_pool_id = aws_cognito_user_pool.users.id
}

resource "aws_cognito_identity_provider" "google" {
  count = var.google_client_secret == null ? 0 : 1

  user_pool_id  = aws_cognito_user_pool.users.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id                     = var.google_client_id
    client_secret                 = var.google_client_secret
    authorize_scopes              = "openid email profile"
    attributes_url_add_attributes = "true"
  }

  attribute_mapping = {
    email    = "email"
    username = "sub"
    name     = "name"
  }
}

# The SPA client lives HERE, not in envs/prod, so its id survives
# deploy-and-destroy and the frontend build config stays stable. Only the
# callback list churns with the CloudFront domain (see var.callback_urls).
resource "aws_cognito_user_pool_client" "spa" {
  name         = "${var.name}-spa"
  user_pool_id = aws_cognito_user_pool.users.id

  generate_secret = false # public SPA client; a secret cannot be kept in a browser

  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers = concat(
    ["COGNITO"],
    var.google_client_secret == null ? [] : ["Google"],
  )

  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  access_token_validity  = 60
  id_token_validity      = 60
  refresh_token_validity = 30
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  prevent_user_existence_errors = "ENABLED"

  depends_on = [aws_cognito_identity_provider.google]
}

# --- Storage --------------------------------------------------------------

# One table holds both trip items (sk = "trip#<iso-timestamp>") and the
# per-user lifetime generation counter (sk = "meta#counter"). The counter only
# ever increments, so deleting trips cannot reset the free-plan cap.
resource "aws_dynamodb_table" "trips" {
  name         = "${var.name}-trips"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "userId"
  range_key    = "sk"

  attribute {
    name = "userId"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  tags = var.tags
}

# --- Secrets --------------------------------------------------------------

# The value is set OUT OF BAND so it never touches Terraform state:
#   aws secretsmanager put-secret-value --secret-id wandor/ai-keys \
#     --secret-string '{"gemini":"...","openrouter":"..."}'
resource "aws_secretsmanager_secret" "ai_keys" {
  name        = "${var.name}/ai-keys"
  description = "AI provider keys read by the wandor API Lambda. Value managed outside Terraform."
  tags        = var.tags
}
