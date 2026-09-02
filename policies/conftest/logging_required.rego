package main

import rego.v1

# The prototype never enabled WAF logging, so its threat detection ran on
# sampled data and every count it produced was unreliable. A Web ACL without a
# logging configuration is therefore not acceptable here.

deny contains msg if {
	acl := input.resource_changes[_]
	acl.type == "aws_wafv2_web_acl"
	acl.change.actions[_] != "delete"

	not has_logging

	msg := sprintf("%s has no aws_wafv2_web_acl_logging_configuration. Without a request log, every detection downstream is guesswork.", [acl.address])
}

has_logging if {
	cfg := input.resource_changes[_]
	cfg.type == "aws_wafv2_web_acl_logging_configuration"
}
