#------------------------------------------------------------------------------
# CloudWatch Monitoring Module - Security Event Aggregator
# Creates dashboards, alarms, and log insights for observability
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# CloudWatch Dashboard
#------------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Row 1: Service Health Overview
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# 🛡️ Security Event Aggregator - Operations Dashboard"
        }
      },
      
      # Row 2: ECS Service Metrics
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 8
        height = 6
        properties = {
          title  = "API Gateway - CPU & Memory"
          region = var.aws_region
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-api-gateway", { label = "CPU %" }],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-api-gateway", { label = "Memory %" }]
          ]
          period = 300
          stat   = "Average"
          yAxis = {
            left = { min = 0, max = 100 }
          }
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 1
        width  = 8
        height = 6
        properties = {
          title  = "Event Ingest - CPU & Memory"
          region = var.aws_region
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-event-ingest", { label = "CPU %" }],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-event-ingest", { label = "Memory %" }]
          ]
          period = 300
          stat   = "Average"
          yAxis = {
            left = { min = 0, max = 100 }
          }
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 1
        width  = 8
        height = 6
        properties = {
          title  = "Event Processor - CPU & Memory"
          region = var.aws_region
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-event-processor", { label = "CPU %" }],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-event-processor", { label = "Memory %" }]
          ]
          period = 300
          stat   = "Average"
          yAxis = {
            left = { min = 0, max = 100 }
          }
        }
      },

      # Row 3: Running Tasks
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 24
        height = 4
        properties = {
          title  = "ECS Running Tasks"
          region = var.aws_region
          metrics = [
            ["ECS/ContainerInsights", "RunningTaskCount", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-api-gateway", { label = "API Gateway" }],
            ["ECS/ContainerInsights", "RunningTaskCount", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-event-ingest", { label = "Event Ingest" }],
            ["ECS/ContainerInsights", "RunningTaskCount", "ClusterName", var.ecs_cluster_name, "ServiceName", "${var.project_name}-event-processor", { label = "Event Processor" }]
          ]
          period = 60
          stat   = "Average"
        }
      },

      # Row 4: ALB Metrics
      {
        type   = "metric"
        x      = 0
        y      = 11
        width  = 8
        height = 6
        properties = {
          title  = "ALB Request Count"
          region = var.aws_region
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_arn_suffix, { stat = "Sum", label = "Requests" }]
          ]
          period = 60
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 11
        width  = 8
        height = 6
        properties = {
          title  = "ALB Response Time"
          region = var.aws_region
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.alb_arn_suffix, { stat = "Average", label = "Avg Response Time" }],
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.alb_arn_suffix, { stat = "p99", label = "p99 Response Time" }]
          ]
          period = 60
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 11
        width  = 8
        height = 6
        properties = {
          title  = "ALB HTTP Errors"
          region = var.aws_region
          metrics = [
            ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", var.alb_arn_suffix, { stat = "Sum", label = "4XX Errors", color = "#ff7f0e" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", var.alb_arn_suffix, { stat = "Sum", label = "5XX Errors", color = "#d62728" }]
          ]
          period = 60
        }
      },

      # Row 5: DynamoDB Metrics
      {
        type   = "metric"
        x      = 0
        y      = 17
        width  = 12
        height = 6
        properties = {
          title  = "DynamoDB Read/Write Capacity"
          region = var.aws_region
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", var.dynamodb_table_name, { stat = "Sum", label = "Read Units" }],
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", var.dynamodb_table_name, { stat = "Sum", label = "Write Units" }]
          ]
          period = 60
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 17
        width  = 12
        height = 6
        properties = {
          title  = "DynamoDB Latency"
          region = var.aws_region
          metrics = [
            ["AWS/DynamoDB", "SuccessfulRequestLatency", "TableName", var.dynamodb_table_name, "Operation", "GetItem", { stat = "Average", label = "GetItem Latency" }],
            ["AWS/DynamoDB", "SuccessfulRequestLatency", "TableName", var.dynamodb_table_name, "Operation", "PutItem", { stat = "Average", label = "PutItem Latency" }],
            ["AWS/DynamoDB", "SuccessfulRequestLatency", "TableName", var.dynamodb_table_name, "Operation", "Query", { stat = "Average", label = "Query Latency" }]
          ]
          period = 60
        }
      },

      # Row 6: SQS Metrics
      {
        type   = "metric"
        x      = 0
        y      = 23
        width  = 12
        height = 6
        properties = {
          title  = "SQS Queue Depth"
          region = var.aws_region
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.sqs_queue_name, { stat = "Average", label = "Messages Waiting" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesNotVisible", "QueueName", var.sqs_queue_name, { stat = "Average", label = "Messages In Flight" }]
          ]
          period = 60
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 23
        width  = 12
        height = 6
        properties = {
          title  = "SQS Message Age"
          region = var.aws_region
          metrics = [
            ["AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName", var.sqs_queue_name, { stat = "Maximum", label = "Oldest Message Age (seconds)" }]
          ]
          period = 60
        }
      },

      # Row 7: Security Events (Custom Metrics)
      {
        type   = "text"
        x      = 0
        y      = 29
        width  = 24
        height = 1
        properties = {
          markdown = "## 🔒 Security Event Metrics"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 30
        width  = 12
        height = 6
        properties = {
          title  = "Recent Critical Events"
          region = var.aws_region
          query  = "SOURCE '/ecs/${var.project_name}/event-processor' | fields @timestamp, @message | filter @message like /CRITICAL/ | sort @timestamp desc | limit 20"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 30
        width  = 12
        height = 6
        properties = {
          title  = "Correlation Alerts"
          region = var.aws_region
          query  = "SOURCE '/ecs/${var.project_name}/event-processor' | fields @timestamp, @message | filter @message like /correlation/ | sort @timestamp desc | limit 20"
        }
      }
    ]
  })
}

#------------------------------------------------------------------------------
# CloudWatch Alarms
#------------------------------------------------------------------------------

# API Gateway High CPU
resource "aws_cloudwatch_metric_alarm" "api_gateway_cpu" {
  alarm_name          = "${var.project_name}-api-gateway-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "API Gateway CPU utilization is above 80%"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = "${var.project_name}-api-gateway"
  }

  tags = var.tags
}

# Event Processor High CPU
resource "aws_cloudwatch_metric_alarm" "event_processor_cpu" {
  alarm_name          = "${var.project_name}-event-processor-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Event Processor CPU utilization is above 80%"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = "${var.project_name}-event-processor"
  }

  tags = var.tags
}

# ALB 5XX Errors
resource "aws_cloudwatch_metric_alarm" "alb_5xx_errors" {
  alarm_name          = "${var.project_name}-alb-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "ALB is returning more than 10 5XX errors in 5 minutes"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  tags = var.tags
}

# ALB High Latency
resource "aws_cloudwatch_metric_alarm" "alb_high_latency" {
  alarm_name          = "${var.project_name}-alb-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Average"
  threshold           = 2
  alarm_description   = "ALB average response time is above 2 seconds"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  tags = var.tags
}

# SQS Queue Depth (messages backing up)
resource "aws_cloudwatch_metric_alarm" "sqs_queue_depth" {
  alarm_name          = "${var.project_name}-sqs-high-queue-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Average"
  threshold           = 100
  alarm_description   = "SQS queue has more than 100 messages waiting"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]

  dimensions = {
    QueueName = var.sqs_queue_name
  }

  tags = var.tags
}

# SQS Message Age (processing delays)
resource "aws_cloudwatch_metric_alarm" "sqs_message_age" {
  alarm_name          = "${var.project_name}-sqs-old-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 300  # 5 minutes
  alarm_description   = "SQS has messages older than 5 minutes"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]

  dimensions = {
    QueueName = var.sqs_queue_name
  }

  tags = var.tags
}

# DynamoDB Throttling
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttle" {
  alarm_name          = "${var.project_name}-dynamodb-throttling"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "DynamoDB is throttling requests"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = var.dynamodb_table_name
  }

  tags = var.tags
}

# ECS Service Task Count (service degradation)
resource "aws_cloudwatch_metric_alarm" "api_gateway_task_count" {
  alarm_name          = "${var.project_name}-api-gateway-no-tasks"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RunningTaskCount"
  namespace           = "ECS/ContainerInsights"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "API Gateway has no running tasks!"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = "${var.project_name}-api-gateway"
  }

  tags = var.tags
}

#------------------------------------------------------------------------------
# CloudWatch Log Metric Filters
#------------------------------------------------------------------------------

# Count of critical security events
resource "aws_cloudwatch_log_metric_filter" "critical_events" {
  name           = "${var.project_name}-critical-events"
  pattern        = "{ $.severity = \"CRITICAL\" }"
  log_group_name = "/ecs/${var.project_name}/event-processor"

  metric_transformation {
    name          = "CriticalSecurityEvents"
    namespace     = "${var.project_name}/SecurityMetrics"
    value         = "1"
    default_value = "0"
  }
}

# Alarm on critical events
resource "aws_cloudwatch_metric_alarm" "critical_events" {
  alarm_name          = "${var.project_name}-critical-security-events"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CriticalSecurityEvents"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Critical security events detected!"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.tags
}

# Count of correlation alerts
resource "aws_cloudwatch_log_metric_filter" "correlation_alerts" {
  name           = "${var.project_name}-correlation-alerts"
  pattern        = "correlation"
  log_group_name = "/ecs/${var.project_name}/event-processor"

  metric_transformation {
    name          = "CorrelationAlerts"
    namespace     = "${var.project_name}/SecurityMetrics"
    value         = "1"
    default_value = "0"
  }
}

#------------------------------------------------------------------------------
# CloudWatch Log Insights Queries (saved)
#------------------------------------------------------------------------------
resource "aws_cloudwatch_query_definition" "security_events_by_severity" {
  name = "${var.project_name}/Security Events by Severity"

  log_group_names = [
    "/ecs/${var.project_name}/event-processor"
  ]

  query_string = <<-EOT
    fields @timestamp, @message
    | filter @message like /severity/
    | parse @message '"severity": "*"' as severity
    | stats count(*) by severity
    | sort count desc
  EOT
}

resource "aws_cloudwatch_query_definition" "top_event_sources" {
  name = "${var.project_name}/Top Event Sources"

  log_group_names = [
    "/ecs/${var.project_name}/event-ingest"
  ]

  query_string = <<-EOT
    fields @timestamp, @message
    | filter @message like /source/
    | parse @message '"source": "*"' as source
    | stats count(*) by source
    | sort count desc
    | limit 10
  EOT
}

resource "aws_cloudwatch_query_definition" "error_analysis" {
  name = "${var.project_name}/Error Analysis"

  log_group_names = [
    "/ecs/${var.project_name}/api-gateway",
    "/ecs/${var.project_name}/event-ingest",
    "/ecs/${var.project_name}/event-processor"
  ]

  query_string = <<-EOT
    fields @timestamp, @message, @logStream
    | filter @message like /(?i)error|exception|failed/
    | sort @timestamp desc
    | limit 50
  EOT
}
