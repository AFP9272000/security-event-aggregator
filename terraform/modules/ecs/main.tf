#------------------------------------------------------------------------------
# ECS Module - Security Event Aggregator
# Creates ECS Fargate cluster, task definitions, and services
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# ECS Cluster
#------------------------------------------------------------------------------
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-cluster"
  })
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = var.use_fargate_spot ? "FARGATE_SPOT" : "FARGATE"
  }
}

#------------------------------------------------------------------------------
# CloudWatch Log Groups
#------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "services" {
  for_each          = toset(["api-gateway", "event-ingest", "event-processor"])
  name              = "/ecs/${var.project_name}/${each.value}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Service = each.value
  })
}

#------------------------------------------------------------------------------
# Task Definition - API Gateway
#------------------------------------------------------------------------------
resource "aws_ecs_task_definition" "api_gateway" {
  family                   = "${var.project_name}-api-gateway"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_gateway_cpu
  memory                   = var.api_gateway_memory
  execution_role_arn       = var.ecs_execution_role_arn
  task_role_arn            = var.api_gateway_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "api-gateway"
      image     = "${var.ecr_repository_urls["api-gateway"]}:${var.image_tag}"
      essential = true

      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "DYNAMODB_TABLE", value = var.dynamodb_table_name },
        { name = "EVENT_INGEST_URL", value = "http://${var.event_ingest_dns}:8001" },
        { name = "EVENT_PROCESSOR_URL", value = "http://${var.event_processor_dns}:8002" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.services["api-gateway"].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live', timeout=5)\" || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = merge(var.tags, {
    Service = "api-gateway"
  })
}

#------------------------------------------------------------------------------
# Task Definition - Event Ingest
#------------------------------------------------------------------------------
resource "aws_ecs_task_definition" "event_ingest" {
  family                   = "${var.project_name}-event-ingest"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.event_ingest_cpu
  memory                   = var.event_ingest_memory
  execution_role_arn       = var.ecs_execution_role_arn
  task_role_arn            = var.event_ingest_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "event-ingest"
      image     = "${var.ecr_repository_urls["event-ingest"]}:${var.image_tag}"
      essential = true

      portMappings = [
        {
          containerPort = 8001
          hostPort      = 8001
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "DYNAMODB_TABLE", value = var.dynamodb_table_name },
        { name = "SQS_QUEUE_URL", value = var.sqs_queue_url }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.services["event-ingest"].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8001/health/live', timeout=5)\" || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = merge(var.tags, {
    Service = "event-ingest"
  })
}

#------------------------------------------------------------------------------
# Task Definition - Event Processor
#------------------------------------------------------------------------------
resource "aws_ecs_task_definition" "event_processor" {
  family                   = "${var.project_name}-event-processor"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.event_processor_cpu
  memory                   = var.event_processor_memory
  execution_role_arn       = var.ecs_execution_role_arn
  task_role_arn            = var.event_processor_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "event-processor"
      image     = "${var.ecr_repository_urls["event-processor"]}:${var.image_tag}"
      essential = true

      portMappings = [
        {
          containerPort = 8002
          hostPort      = 8002
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "DYNAMODB_TABLE", value = var.dynamodb_table_name },
        { name = "SQS_QUEUE_URL", value = var.sqs_queue_url },
        { name = "SNS_TOPIC_ARN", value = var.sns_topic_arn },
        { name = "BATCH_SIZE", value = "10" },
        { name = "POLL_INTERVAL_SECONDS", value = "5" },
        { name = "CORRELATION_WINDOW_MINUTES", value = "60" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.services["event-processor"].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8002/health/live', timeout=5)\" || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = merge(var.tags, {
    Service = "event-processor"
  })
}

#------------------------------------------------------------------------------
# ECS Service - API Gateway
#------------------------------------------------------------------------------
resource "aws_ecs_service" "api_gateway" {
  name                               = "${var.project_name}-api-gateway"
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.api_gateway.arn
  desired_count                      = var.api_gateway_desired_count
  launch_type                        = var.use_fargate_spot ? null : "FARGATE"
  platform_version                   = "LATEST"
  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  dynamic "capacity_provider_strategy" {
    for_each = var.use_fargate_spot ? [1] : []
    content {
      capacity_provider = "FARGATE_SPOT"
      weight            = 100
    }
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.api_gateway_target_group_arn
    container_name   = "api-gateway"
    container_port   = 8000
  }

  service_registries {
    registry_arn = var.api_gateway_service_registry_arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = merge(var.tags, {
    Service = "api-gateway"
  })

  lifecycle {
    ignore_changes = [desired_count]
  }
}

#------------------------------------------------------------------------------
# ECS Service - Event Ingest
#------------------------------------------------------------------------------
resource "aws_ecs_service" "event_ingest" {
  name                               = "${var.project_name}-event-ingest"
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.event_ingest.arn
  desired_count                      = var.event_ingest_desired_count
  launch_type                        = var.use_fargate_spot ? null : "FARGATE"
  platform_version                   = "LATEST"
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  dynamic "capacity_provider_strategy" {
    for_each = var.use_fargate_spot ? [1] : []
    content {
      capacity_provider = "FARGATE_SPOT"
      weight            = 100
    }
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = var.event_ingest_service_registry_arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = merge(var.tags, {
    Service = "event-ingest"
  })

  lifecycle {
    ignore_changes = [desired_count]
  }
}

#------------------------------------------------------------------------------
# ECS Service - Event Processor
#------------------------------------------------------------------------------
resource "aws_ecs_service" "event_processor" {
  name                               = "${var.project_name}-event-processor"
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.event_processor.arn
  desired_count                      = var.event_processor_desired_count
  launch_type                        = var.use_fargate_spot ? null : "FARGATE"
  platform_version                   = "LATEST"
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  dynamic "capacity_provider_strategy" {
    for_each = var.use_fargate_spot ? [1] : []
    content {
      capacity_provider = "FARGATE_SPOT"
      weight            = 100
    }
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = var.event_processor_service_registry_arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = merge(var.tags, {
    Service = "event-processor"
  })

  lifecycle {
    ignore_changes = [desired_count]
  }
}

#------------------------------------------------------------------------------
# Auto Scaling - API Gateway
#------------------------------------------------------------------------------
resource "aws_appautoscaling_target" "api_gateway" {
  count              = var.enable_autoscaling ? 1 : 0
  max_capacity       = var.api_gateway_max_count
  min_capacity       = var.api_gateway_min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.api_gateway.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_gateway_cpu" {
  count              = var.enable_autoscaling ? 1 : 0
  name               = "${var.project_name}-api-gateway-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api_gateway[0].resource_id
  scalable_dimension = aws_appautoscaling_target.api_gateway[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.api_gateway[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

#------------------------------------------------------------------------------
# Auto Scaling - Event Ingest
#------------------------------------------------------------------------------
resource "aws_appautoscaling_target" "event_ingest" {
  count              = var.enable_autoscaling ? 1 : 0
  max_capacity       = var.event_ingest_max_count
  min_capacity       = var.event_ingest_min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.event_ingest.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "event_ingest_cpu" {
  count              = var.enable_autoscaling ? 1 : 0
  name               = "${var.project_name}-event-ingest-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.event_ingest[0].resource_id
  scalable_dimension = aws_appautoscaling_target.event_ingest[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.event_ingest[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

#------------------------------------------------------------------------------
# Auto Scaling - Event Processor
#------------------------------------------------------------------------------
resource "aws_appautoscaling_target" "event_processor" {
  count              = var.enable_autoscaling ? 1 : 0
  max_capacity       = var.event_processor_max_count
  min_capacity       = var.event_processor_min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.event_processor.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "event_processor_cpu" {
  count              = var.enable_autoscaling ? 1 : 0
  name               = "${var.project_name}-event-processor-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.event_processor[0].resource_id
  scalable_dimension = aws_appautoscaling_target.event_processor[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.event_processor[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
