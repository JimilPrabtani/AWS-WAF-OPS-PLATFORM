output "security_topic_arn" {
  value = aws_sns_topic.security.arn
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.id
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}
