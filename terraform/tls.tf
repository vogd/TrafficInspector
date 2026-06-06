# Self-signed CA for outbound TLS inspection (MITM). NFW signs on-the-fly server certs with it.
# AWS Private CA is NOT supported for this; an imported self-signed CA is the required approach.
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem       = tls_private_key.ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = 8760
  subject {
    common_name  = "TrafInspector Inspection CA"
    organization = "TrafInspector"
  }
  allowed_uses = ["cert_signing", "crl_signing", "digital_signature"]
}

resource "aws_acm_certificate" "ca" {
  private_key      = tls_private_key.ca.private_key_pem
  certificate_body = tls_self_signed_cert.ca.cert_pem
  tags             = var.tags
}
