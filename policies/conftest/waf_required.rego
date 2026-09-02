package main

import rego.v1

# No internet-facing entry point may be created without a Web ACL. This is the
# project's central claim expressed as a gate: if someone later adds a
# distribution and forgets the WAF, the pipeline fails rather than the site
# quietly becoming unprotected.

deny contains msg if {
	dist := input.resource_changes[_]
	dist.type == "aws_cloudfront_distribution"
	dist.change.actions[_] != "delete"

	not dist.change.after.web_acl_id

	msg := sprintf("%s has no web_acl_id. An unprotected distribution is the defect this project exists to fix.", [dist.address])
}

deny contains msg if {
	lb := input.resource_changes[_]
	lb.type == "aws_lb"
	lb.change.after.internal == false
	lb.change.actions[_] != "delete"

	not has_association

	msg := sprintf("%s is internet-facing but no aws_wafv2_web_acl_association is planned.", [lb.address])
}

has_association if {
	assoc := input.resource_changes[_]
	assoc.type == "aws_wafv2_web_acl_association"
}
