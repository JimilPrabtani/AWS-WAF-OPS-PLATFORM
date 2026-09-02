terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Deliberately LOCAL state.
  #
  # This configuration creates the bucket that every other configuration stores
  # its state in, so it cannot store its own state there. Run it once, by hand,
  # with credentials you already have. terraform.tfstate here is gitignored --
  # if you lose it, import the four or five resources rather than re-creating
  # them.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project   = "waf-ops-platform"
      component = "bootstrap"
      managedBy = "terraform"
    }
  }
}
