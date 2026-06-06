terraform {
  required_version = ">= 1.5"

  # Backend: local by default. For remote state, configure S3 or HTTP backend.
  # backend "s3" { bucket = "..." key = "trafinspector/terraform.tfstate" region = "us-east-2" }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}
