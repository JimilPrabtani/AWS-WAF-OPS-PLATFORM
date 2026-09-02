terraform {
  backend "s3" {
    # Fill these in from `terraform -chdir=bootstrap output`, then run
    # `terraform init`. Backend blocks cannot use variables -- that is a
    # Terraform limitation, not an oversight.
    bucket = "REPLACE_ME_STATE_BUCKET"
    key    = "envs/prod/terraform.tfstate"
    region = "us-east-1"

    # Native S3 locking (Terraform >= 1.11 / OpenTofu >= 1.11). Writes a .tflock
    # object alongside the state. The DynamoDB table older guides describe is no
    # longer required.
    use_lockfile = true
    encrypt      = true
  }
}
