# AZ -> firewall endpoint id (from the firewall's sync states)
locals {
  fw_sync      = tolist(aws_networkfirewall_firewall.fw.firewall_status[0].sync_states)
  fw_endpoints = { for s in local.fw_sync : s.availability_zone => tolist(s.attachment)[0].endpoint_id }
  az_spoke = { for p in setproduct(range(local.az_count), var.spoke_cidrs) :
  "${p[0]}-${p[1]}" => { az_idx = p[0], cidr = p[1] } }
}

# TGW subnet: spoke traffic arriving from TGW -> firewall endpoint (same AZ)
resource "aws_route_table" "tgw" {
  count  = local.az_count
  vpc_id = aws_vpc.inspection.id
  tags   = merge(var.tags, { Name = "rt-tgw-${var.azs[count.index]}" })
}
resource "aws_route" "tgw_to_fw" {
  count                  = local.az_count
  route_table_id         = aws_route_table.tgw[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = local.fw_endpoints[var.azs[count.index]]
}
resource "aws_route_table_association" "tgw" {
  count          = local.az_count
  subnet_id      = aws_subnet.tgw[count.index].id
  route_table_id = aws_route_table.tgw[count.index].id
}

# Firewall subnet: egress -> NAT (same AZ); return to spokes -> TGW
resource "aws_route_table" "firewall" {
  count  = local.az_count
  vpc_id = aws_vpc.inspection.id
  tags   = merge(var.tags, { Name = "rt-fw-${var.azs[count.index]}" })
}
resource "aws_route" "fw_default" {
  count                  = local.az_count
  route_table_id         = aws_route_table.firewall[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[count.index].id
}
resource "aws_route" "fw_to_spokes" {
  for_each               = local.az_spoke
  route_table_id         = aws_route_table.firewall[each.value.az_idx].id
  destination_cidr_block = each.value.cidr
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id
}
resource "aws_route_table_association" "firewall" {
  count          = local.az_count
  subnet_id      = aws_subnet.firewall[count.index].id
  route_table_id = aws_route_table.firewall[count.index].id
}

# Public subnet: egress -> IGW; return to spokes -> firewall endpoint (inspect return path)
resource "aws_route_table" "public" {
  count  = local.az_count
  vpc_id = aws_vpc.inspection.id
  tags   = merge(var.tags, { Name = "rt-public-${var.azs[count.index]}" })
}
resource "aws_route" "public_default" {
  count                  = local.az_count
  route_table_id         = aws_route_table.public[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}
resource "aws_route" "public_to_fw" {
  for_each               = local.az_spoke
  route_table_id         = aws_route_table.public[each.value.az_idx].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = local.fw_endpoints[var.azs[each.value.az_idx]]
}
resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[count.index].id
}

# Inspection-side TGW route table. Spoke attachment + spoke->inspection default route
# are added by the test-traffic infra (where the spoke attachment exists).
resource "aws_ec2_transit_gateway_route_table" "inspection" {
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  tags               = merge(var.tags, { Name = "tgw-rt-inspection" })
}
resource "aws_ec2_transit_gateway_route_table_association" "inspection" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspection.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}
