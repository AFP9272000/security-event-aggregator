#------------------------------------------------------------------------------
# SQS Module - Security Event Aggregator
# Creates SQS queue for event processing and SNS topic for alerts
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# SQS Queue for Event Processing
#------------------------------------------------------------------------------
resource "aws_sqs_queue" "events" {
  name                       = "${var.project_name}-events-queue"
  delay_seconds              = 0
  max_message_size           = 262144 # 256 KB
  message_retention_seconds  = var.message_retention_seconds
  receive_wait_time_seconds  = var.receive_wait_time_seconds
  visibility_timeout_seconds = var.visibility_timeout_seconds

  # Enable server-side encryption
  sqs_managed_sse_enabled = true

  # Redrive policy for failed messages
  redrive_policy = var.enable_dlq ? jsonencode({
    deadLetterTargetArn = aws_sqs_queue.events_dlq[0].arn
    maxReceiveCount     = var.max_receive_count
  }) : null

  tags = merge(var.tags, {
    Name = "${var.project_name}-events-queue"
  })
}

#------------------------------------------------------------------------------
# Dead Letter Queue
#------------------------------------------------------------------------------
resource "aws_sqs_queue" "events_dlq" {
  count                      = var.enable_dlq ? 1 : 0
  name                       = "${var.project_name}-events-dlq"
  message_retention_seconds  = 1209600 # 14 days
  sqs_managed_sse_enabled    = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-events-dlq"
  })
}

#------------------------------------------------------------------------------
# SNS Topic for Security Alerts
#------------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-security-alerts"

  # Enable server-side encryption
  kms_master_key_id = var.sns_kms_key_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-security-alerts"
  })
}

#------------------------------------------------------------------------------
# SNS Topic Policy
#------------------------------------------------------------------------------
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowECSPublish"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

#------------------------------------------------------------------------------
# Email Subscription (optional)
#------------------------------------------------------------------------------
resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

#------------------------------------------------------------------------------
# CloudWatch Alarm for DLQ Messages
#------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  count               = var.enable_dlq ? 1 : 0
  alarm_name          = "${var.project_name}-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert when messages appear in the DLQ"

  dimensions = {
    QueueName = aws_sqs_queue.events_dlq[0].name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = var.tags
}
