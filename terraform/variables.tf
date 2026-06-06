variable "region" {
  type    = string
  default = "us-east-2"
}

variable "azs" {
  type    = list(string)
  default = ["us-east-2a", "us-east-2b"]
}

variable "inspection_cidr" {
  type    = string
  default = "10.100.0.0/16"
}

variable "spoke_cidrs" {
  description = "Spoke/test VPC CIDRs whose traffic is routed through inspection"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

# ARN of an ACM-imported CA cert for OUTBOUND TLS inspection (MITM).
# Empty => deploy firewall without TLS inspection (SNI-only visibility).
variable "tls_ca_cert_arn" {
  type    = string
  default = ""
}

variable "tags" {
  type    = map(string)
  default = { Project = "TrafInspector", env = "dev" }
}
