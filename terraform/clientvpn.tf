variable "vpn_client_cidr" {
  type    = string
  default = "10.20.0.0/22" # must not overlap spoke/inspection VPC CIDRs
}

# --- Server + client certs, signed by our inspection CA (tls.tf) ---
resource "tls_private_key" "vpn_server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
resource "tls_cert_request" "vpn_server" {
  private_key_pem = tls_private_key.vpn_server.private_key_pem
  dns_names       = ["server.trafinspector.vpn"]
  subject { common_name = "server.trafinspector.vpn" }
}
resource "tls_locally_signed_cert" "vpn_server" {
  cert_request_pem      = tls_cert_request.vpn_server.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = 8760
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
}
resource "aws_acm_certificate" "vpn_server" {
  private_key       = tls_private_key.vpn_server.private_key_pem
  certificate_body  = tls_locally_signed_cert.vpn_server.cert_pem
  certificate_chain = tls_self_signed_cert.ca.cert_pem
  tags              = var.tags
}

resource "tls_private_key" "vpn_client" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
resource "tls_cert_request" "vpn_client" {
  private_key_pem = tls_private_key.vpn_client.private_key_pem
  subject { common_name = "trafinspector-vpn-client" }
}
resource "tls_locally_signed_cert" "vpn_client" {
  cert_request_pem      = tls_cert_request.vpn_client.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = 8760
  allowed_uses          = ["key_encipherment", "digital_signature", "client_auth"]
}

# --- Client VPN endpoint (full tunnel -> all device traffic goes through inspection) ---
resource "aws_cloudwatch_log_group" "vpn" {
  name              = "/trafinspector/clientvpn"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_ec2_client_vpn_endpoint" "vpn" {
  description            = "trafinspector client vpn"
  server_certificate_arn = aws_acm_certificate.vpn_server.arn
  client_cidr_block      = var.vpn_client_cidr
  split_tunnel           = false
  vpc_id                 = aws_vpc.spoke.id
  dns_servers            = ["8.8.8.8", "8.8.4.4"]
  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.vpn_server.arn
  }
  connection_log_options {
    enabled              = true
    cloudwatch_log_group = aws_cloudwatch_log_group.vpn.name
  }
  tags = var.tags
}

resource "aws_ec2_client_vpn_network_association" "vpn" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.vpn.id
  subnet_id              = aws_subnet.spoke.id
}
resource "aws_ec2_client_vpn_authorization_rule" "vpn" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.vpn.id
  target_network_cidr    = "0.0.0.0/0"
  authorize_all_groups   = true
}
resource "aws_ec2_client_vpn_route" "internet" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.vpn.id
  destination_cidr_block = "0.0.0.0/0"
  target_vpc_subnet_id   = aws_subnet.spoke.id
}

# --- Return path for the VPN client CIDR: internet -> NAT -> firewall -> TGW -> spoke -> client ---
resource "aws_route" "public_vpn_return" {
  count                  = local.az_count
  route_table_id         = aws_route_table.public[count.index].id
  destination_cidr_block = var.vpn_client_cidr
  vpc_endpoint_id        = local.fw_endpoints[var.azs[count.index]]
}
resource "aws_route" "fw_vpn_return" {
  count                  = local.az_count
  route_table_id         = aws_route_table.firewall[count.index].id
  destination_cidr_block = var.vpn_client_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id
}
resource "aws_ec2_transit_gateway_route" "vpn_return" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
  destination_cidr_block         = var.vpn_client_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.spoke.id
}

output "clientvpn_endpoint_id" {
  value = aws_ec2_client_vpn_endpoint.vpn.id
}
output "vpn_client_cert_pem" {
  value = tls_locally_signed_cert.vpn_client.cert_pem
}
output "vpn_client_key_pem" {
  value     = tls_private_key.vpn_client.private_key_pem
  sensitive = true
}
