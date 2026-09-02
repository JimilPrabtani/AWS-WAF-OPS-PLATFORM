# ---------------------------------------------------------------------------
# Remote state.
#
# The prototype kept deployment state in a gitignored local JSON file, which no
# second machine and no CI runner ever had. That is the concrete reason this
# project needed Terraform at all, and this bucket is the replacement.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket_name

  # No force_destroy. State is the one thing in this repository that must not be
  # casually destroyable.
  lifecycle {
    prevent_destroy = true
  }
}

# Versioning is what makes a corrupted or truncated state recoverable. It is not
# optional on a state bucket.
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Old state versions are useful for a while and then are just cost.
resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-noncurrent-state"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# NOTE: no DynamoDB lock table.
#
# Terraform 1.11+ and OpenTofu 1.11+ support native S3 state locking via a
# .tflock object in the state bucket (`use_lockfile = true` in the backend
# block). The DynamoDB table that older guides tell you to create is no longer
# needed, and it was an always-on resource in an otherwise ephemeral project.
