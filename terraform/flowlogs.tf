resource "aws_cloudwatch_log_group" "flow" {
  name              = "/trafinspector/flowlogs"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_iam_role" "flow" {
  name = "trafinspector-flowlogs"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "flow" {
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

# Custom format keeps original IPs (pkt-*) that survive the TGW/NAT hops.
resource "aws_flow_log" "inspection" {
  vpc_id                   = aws_vpc.inspection.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.flow.arn
  max_aggregation_interval = 60
  log_format               = "$${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${pkt-srcaddr} $${pkt-dstaddr} $${bytes} $${packets} $${action} $${flow-direction} $${start} $${end} $${tcp-flags} $${type} $${vpc-id} $${subnet-id} $${interface-id} $${log-status} $${traffic-path} $${pkt-dst-aws-service} $${pkt-src-aws-service}"
  tags                     = var.tags
}
