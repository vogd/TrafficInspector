output "transit_gateway_id" {
  value = aws_ec2_transit_gateway.tgw.id
}

output "tgw_inspection_route_table_id" {
  value = aws_ec2_transit_gateway_route_table.inspection.id
}

output "inspection_vpc_id" {
  value = aws_vpc.inspection.id
}

output "firewall_endpoints" {
  description = "AZ -> Network Firewall endpoint id"
  value       = local.fw_endpoints
}

output "tls_inspection_enabled" {
  value = true
}
