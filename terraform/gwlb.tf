# Vendor-agnostic 3rd-party inspection scaffold (Palo Alto / Fortinet / Check Point / Cisco / ...).
# NO appliances provisioned yet. The GWLB endpoint (GWLBE) and inline route-chaining are added
# only once appliances are registered, so this never blackholes live traffic.

variable "appliance_ami_id" {
  description = "GENEVE-capable inspection appliance AMI (e.g. Palo Alto VM-Series). Empty = scaffold only."
  type        = string
  default     = ""
}

resource "aws_lb" "gwlb" {
  name               = "trafinspector-gwlb"
  load_balancer_type = "gateway"
  subnets            = aws_subnet.firewall[*].id
  tags               = var.tags
}

# Appliances register here later (GENEVE/6081). Empty target group for now.
resource "aws_lb_target_group" "appliances" {
  name        = "trafinspector-appliances"
  target_type = "instance"
  protocol    = "GENEVE"
  port        = 6081
  vpc_id      = aws_vpc.inspection.id
  health_check {
    protocol = "TCP"
    port     = 80
  }
  tags = var.tags
}

resource "aws_lb_listener" "gwlb" {
  load_balancer_arn = aws_lb.gwlb.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.appliances.arn
  }
}

# Endpoint service: a GWLBE consumes this to chain the appliance fleet inline (added with appliances).
resource "aws_vpc_endpoint_service" "gwlb" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.gwlb.arn]
  tags                       = var.tags
}

output "gwlb_endpoint_service_name" {
  value = aws_vpc_endpoint_service.gwlb.service_name
}
output "appliance_target_group_arn" {
  description = "Register vendor appliance instances here, then create a GWLBE and chain it after NFW."
  value       = aws_lb_target_group.appliances.arn
}
