data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

locals {
  spoke_cidr   = var.spoke_cidrs[0]
  spoke_subnet = cidrsubnet(local.spoke_cidr, 8, 0)
  gen_b64      = base64encode(file("${path.module}/traffic-gen.sh"))
  ca_b64       = base64encode(tls_self_signed_cert.ca.cert_pem)
}

resource "aws_vpc" "spoke" {
  cidr_block           = local.spoke_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "spoke-test-vpc" })
}

resource "aws_subnet" "spoke" {
  vpc_id            = aws_vpc.spoke.id
  availability_zone = var.azs[0]
  cidr_block        = local.spoke_subnet
  tags              = merge(var.tags, { Name = "spoke-test" })
}

# --- TGW wiring: spoke -> inspection (and return) ---
resource "aws_ec2_transit_gateway_vpc_attachment" "spoke" {
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  vpc_id             = aws_vpc.spoke.id
  subnet_ids         = [aws_subnet.spoke.id]
  tags               = merge(var.tags, { Name = "tgw-attach-spoke" })
}

resource "aws_ec2_transit_gateway_route_table" "spoke" {
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  tags               = merge(var.tags, { Name = "tgw-rt-spoke" })
}
resource "aws_ec2_transit_gateway_route_table_association" "spoke" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.spoke.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}
resource "aws_ec2_transit_gateway_route" "spoke_default" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspection.id
}
resource "aws_ec2_transit_gateway_route" "return_to_spoke" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
  destination_cidr_block         = local.spoke_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.spoke.id
}

# Spoke subnet: all egress -> TGW (no IGW; internet egress happens from the inspection VPC)
resource "aws_route_table" "spoke" {
  vpc_id = aws_vpc.spoke.id
  tags   = merge(var.tags, { Name = "rt-spoke" })
}
resource "aws_route" "spoke_to_tgw" {
  route_table_id         = aws_route_table.spoke.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.spoke]
}
resource "aws_route_table_association" "spoke" {
  subnet_id      = aws_subnet.spoke.id
  route_table_id = aws_route_table.spoke.id
}

# --- Client EC2 removed — testing done via VPN-connected laptop ---
# To re-add a test instance: uncomment in git history (commit before removal)

output "client_instance_id" {
  value = "none — use VPN"
}
