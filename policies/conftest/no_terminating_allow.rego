package main

import rego.v1

# THE PROTOTYPE'S BYPASS, AS A POLICY GATE.
#
# WAFv2 evaluates rules in priority order and a terminating ALLOW ends
# evaluation for that request. The prototype placed an ALLOW-on-IP-set rule at
# priority 0, which meant any address in that set skipped injection rules, rate
# limiting, managed rule groups -- everything.
#
# The module already rejects this in a variable validation. This is the second
# line of defence, at the plan level, so a hand-written resource cannot
# reintroduce it either.

deny contains msg if {
	acl := input.resource_changes[_]
	acl.type == "aws_wafv2_web_acl"
	rule := acl.change.after.rule[_]
	count(rule.action[_].allow) > 0

	msg := sprintf(
		"%s rule %q uses a terminating ALLOW action. Express trusted addresses as a NotStatement scope-down inside individual rules instead.",
		[acl.address, rule.name],
	)
}
