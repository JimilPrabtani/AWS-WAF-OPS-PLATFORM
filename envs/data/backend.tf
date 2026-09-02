terraform {
  backend "s3" {
    # Fill in from `terraform -chdir=bootstrap output`, same bucket as the other
    # environments. Backend blocks cannot use variables.
    bucket = "REPLACE_ME_STATE_BUCKET"
    key    = "envs/data/terraform.tfstate"
    region = "us-east-1"

    use_lockfile = true
    encrypt      = true
  }
}
