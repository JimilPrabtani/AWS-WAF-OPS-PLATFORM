# ---------------------------------------------------------------------------
# CloudWatch RUM: real-user monitoring for the SPA.
#
# Lives in this persistent root (not envs/prod) so the monitor id, identity
# pool id and guest role ARN stay stable -- they are baked into the frontend
# bundle as VITE_RUM_* values, and a per-deploy id would force a rebuild every
# cycle. RUM bills per event received; idle cost is zero.
# ---------------------------------------------------------------------------

# RUM's browser client signs its PutRumEvents calls with credentials from an
# unauthenticated Cognito identity. The guest role can do exactly one thing.
resource "aws_cognito_identity_pool" "rum" {
  identity_pool_name               = "${var.name}-rum"
  allow_unauthenticated_identities = true
  tags                             = var.tags
}

data "aws_iam_policy_document" "rum_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"
      values   = [aws_cognito_identity_pool.rum.id]
    }

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"
      values   = ["unauthenticated"]
    }
  }
}

resource "aws_iam_role" "rum_guest" {
  name               = "${var.name}-rum-guest"
  assume_role_policy = data.aws_iam_policy_document.rum_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "rum_guest" {
  statement {
    actions   = ["rum:PutRumEvents"]
    resources = ["arn:aws:rum:${var.region}:${data.aws_caller_identity.current.account_id}:appmonitor/${var.name}"]
  }
}

resource "aws_iam_role_policy" "rum_guest" {
  name   = "put-rum-events-only"
  role   = aws_iam_role.rum_guest.id
  policy = data.aws_iam_policy_document.rum_guest.json
}

resource "aws_cognito_identity_pool_roles_attachment" "rum" {
  identity_pool_id = aws_cognito_identity_pool.rum.id

  roles = {
    unauthenticated = aws_iam_role.rum_guest.arn
    # RUM only uses the guest identity; authenticated gets the same
    # do-one-thing role rather than something broader.
    authenticated = aws_iam_role.rum_guest.arn
  }
}

resource "aws_rum_app_monitor" "spa" {
  name = var.name

  # The CloudFront domain changes every prod cycle; the wildcard keeps this
  # stable. localhost lets local dev sessions show up when RUM env vars are set.
  domain_list = ["*.cloudfront.net", "localhost"]

  app_monitor_configuration {
    allow_cookies       = false
    enable_xray         = false
    session_sample_rate = 1
    telemetries         = ["errors", "performance", "http"]
    identity_pool_id    = aws_cognito_identity_pool.rum.id
    guest_role_arn      = aws_iam_role.rum_guest.arn
  }

  tags = var.tags
}
