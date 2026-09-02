# Off-the-shelf scanners find generic misconfigurations. These policies encode
# the specific defects THIS project was built to fix, which is the part worth
# showing. Run against a plan:
#
#   terraform show -json tfplan > tfplan.json
#   conftest test --policy policies/conftest tfplan.json

package main

import rego.v1

# The prototype disabled all four Block Public Access settings and then attached
# a Principal:"*" policy, which is what made the WAF bypassable. Nothing in this
# repository may ever do that again.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
	setting := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"][_]
	resource.change.after[setting] == false

	msg := sprintf(
		"%s sets %s = false. Block Public Access must stay fully enabled -- a public origin is how the WAF gets bypassed.",
		[resource.address, setting],
	)
}

# A bucket with no public access block at all is worse than one that disables it.
deny contains msg if {
	bucket := input.resource_changes[_]
	bucket.type == "aws_s3_bucket"
	bucket.change.actions[_] == "create"

	not has_public_access_block(bucket.change.after.bucket)

	msg := sprintf(
		"%s is created without a corresponding aws_s3_bucket_public_access_block.",
		[bucket.address],
	)
}

has_public_access_block(bucket_name) if {
	pab := input.resource_changes[_]
	pab.type == "aws_s3_bucket_public_access_block"
	pab.change.after.bucket == bucket_name
}

deny contains msg if {
	policy := input.resource_changes[_]
	policy.type == "aws_s3_bucket_policy"
	contains(policy.change.after.policy, "\"Principal\":\"*\"")

	msg := sprintf("%s grants access to Principal \"*\".", [policy.address])
}
