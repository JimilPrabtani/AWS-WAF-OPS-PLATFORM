output "state_bucket" {
  description = "Put this in every envs/*/backend.tf."
  value       = aws_s3_bucket.state.id
}

output "plan_role_arn" {
  description = "Set as AWS_PLAN_ROLE in the repository's GitHub Actions variables."
  value       = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  description = "Set as AWS_APPLY_ROLE in the repository's GitHub Actions variables."
  value       = aws_iam_role.apply.arn
}

output "human_role_arn" {
  description = "Put this in ~/.aws/config as the role_arn of your wafops-deploy profile."
  value       = length(var.human_principal_arns) > 0 ? aws_iam_role.human[0].arn : null
}

output "aws_config_snippet" {
  description = "Paste into ~/.aws/config, then run everything with AWS_PROFILE=wafops-deploy."
  value       = length(var.human_principal_arns) == 0 ? null : <<-EOT
    [profile wafops-admin]
    region = ${var.region}

    [profile wafops-deploy]
    role_arn       = ${aws_iam_role.human[0].arn}
    source_profile = wafops-admin
    region         = ${var.region}
    mfa_serial     = arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/<YOUR_MFA_DEVICE_NAME>
  EOT
}
