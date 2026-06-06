terraform {
  required_version = ">= 1.5"

  backend "http" {
    address = "https://d11tj92p3kkm7v.cloudfront.net/api/v1/states/backend/c7f039f8-11e6-442e-85cf-05c8b9cab5bf"
  }

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
