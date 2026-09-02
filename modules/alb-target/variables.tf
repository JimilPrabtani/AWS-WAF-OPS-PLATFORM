variable "name" {
  description = "Name prefix for the load balancer and security group."
  type        = string
}

variable "vpc_id" {
  description = "VPC to place the load balancer in. Leave null to use the account's default VPC."
  type        = string
  default     = null
}

variable "ingress_cidrs" {
  description = "Who may reach the listener. Narrow this to your own address if you would rather not have an internet-facing target."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
