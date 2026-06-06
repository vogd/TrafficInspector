locals {
  az_count = length(var.azs)
}

resource "aws_vpc" "inspection" {
  cidr_block           = var.inspection_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "inspection-vpc" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.inspection.id
  tags   = merge(var.tags, { Name = "inspection-igw" })
}

# Per-AZ subnets: firewall (NFW endpoint), tgw (attachment ENIs), public (NAT egress)
resource "aws_subnet" "firewall" {
  count             = local.az_count
  vpc_id            = aws_vpc.inspection.id
  availability_zone = var.azs[count.index]
  cidr_block        = cidrsubnet(var.inspection_cidr, 8, count.index)
  tags              = merge(var.tags, { Name = "fw-${var.azs[count.index]}" })
}

resource "aws_subnet" "tgw" {
  count             = local.az_count
  vpc_id            = aws_vpc.inspection.id
  availability_zone = var.azs[count.index]
  cidr_block        = cidrsubnet(var.inspection_cidr, 8, 10 + count.index)
  tags              = merge(var.tags, { Name = "tgw-${var.azs[count.index]}" })
}

resource "aws_subnet" "public" {
  count             = local.az_count
  vpc_id            = aws_vpc.inspection.id
  availability_zone = var.azs[count.index]
  cidr_block        = cidrsubnet(var.inspection_cidr, 8, 20 + count.index)
  tags              = merge(var.tags, { Name = "public-${var.azs[count.index]}" })
}

resource "aws_eip" "nat" {
  count  = local.az_count
  domain = "vpc"
  tags   = merge(var.tags, { Name = "nat-eip-${var.azs[count.index]}" })
}

resource "aws_nat_gateway" "nat" {
  count         = local.az_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(var.tags, { Name = "nat-${var.azs[count.index]}" })
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_ec2_transit_gateway" "tgw" {
  description                     = "TrafInspector TGW"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  tags                            = merge(var.tags, { Name = "trafinspector-tgw" })
}

# Appliance mode = flow symmetry (request + response hit the same AZ/appliance) — required for stateful TLS inspection
resource "aws_ec2_transit_gateway_vpc_attachment" "inspection" {
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id
  vpc_id                 = aws_vpc.inspection.id
  subnet_ids             = aws_subnet.tgw[*].id
  appliance_mode_support = "enable"
  tags                   = merge(var.tags, { Name = "tgw-attach-inspection" })
}
