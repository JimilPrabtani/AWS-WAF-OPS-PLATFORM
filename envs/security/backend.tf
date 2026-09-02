terraform {
  backend "s3" {
    # Same bucket as the other environments; see bootstrap outputs.
    bucket = "REPLACE_ME_STATE_BUCKET"
    key    = "envs/security/terraform.tfstate"
    region = "us-east-1"

    use_lockfile = true
    encrypt      = true
  }
}
