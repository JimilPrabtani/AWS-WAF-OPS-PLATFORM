# ---------------------------------------------------------------------------
# The dev target.
#
# WHY THIS EXISTS AT ALL
#
# A CloudFront distribution takes 15-20 minutes to deploy and about the same to
# disable and delete. Tuning a WAF rule against CloudFront therefore costs a
# ~40 minute round trip per iteration, which in practice means the rules never
# get tuned. This module brings an equivalent WAF target up in roughly 90
# seconds so rule development is actually possible.
#
# THE TRICK
#
# The listener's default action is `fixed_response` -- the load balancer serves
# the page itself. There is no target group, no EC2 instance, no container, no
# ECS cluster, nothing to keep patched. The ALB is a WAF attachment point and a
# response generator, and nothing else.
#
# It also forces the WAF module to handle REGIONAL scope as well as CLOUDFRONT,
# which is a more interesting piece of module design than either alone.
# ---------------------------------------------------------------------------

data "aws_vpc" "selected" {
  id      = var.vpc_id
  default = var.vpc_id == null ? true : null
}

data "aws_subnets" "selected" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }
}

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Ingress to the WAF-protected dev listener"
  vpc_id      = data.aws_vpc.selected.id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  for_each = toset(var.ingress_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTP from ${each.value}"
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

# The listener answers from a fixed response, so the load balancer never opens
# an outbound connection. An egress rule is required by the API but can be
# effectively empty; this allows nothing useful.
resource "aws_vpc_security_group_egress_rule" "none" {
  security_group_id = aws_security_group.alb.id
  description       = "No egress required for a fixed-response listener"
  cidr_ipv4         = "127.0.0.1/32"
  ip_protocol       = "-1"
}

resource "aws_lb" "this" {
  name               = substr("${var.name}-alb", 0, 32)
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]

  # An ALB requires subnets in at least two availability zones.
  subnets = slice(sort(data.aws_subnets.selected.ids), 0, 2)

  # Ephemeral by design -- `make destroy` must not be blocked.
  enable_deletion_protection = false
  drop_invalid_header_fields = true

  tags = var.tags

  lifecycle {
    precondition {
      condition     = length(data.aws_subnets.selected.ids) >= 2
      error_message = "An Application Load Balancer needs subnets in at least two availability zones, and this VPC has fewer. Either pass a vpc_id with two or more subnets, or recreate the default VPC with: aws ec2 create-default-vpc"
    }
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  # fixed_response message_body is capped at 1024 bytes by the ELB API.
  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/html"
      status_code  = "200"
      message_body = "<!doctype html><title>WAF dev target</title><h1>WAF Ops Platform - dev</h1><p>Served directly by the load balancer. Every request reaching this page passed the Web ACL.</p>"
    }
  }
}
