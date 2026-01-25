variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs"
  type        = list(string)
}

variable "ecs_security_group_id" {
  description = "Security group ID for ECS tasks"
  type        = string
}

variable "ecs_execution_role_arn" {
  description = "ARN of ECS task execution role"
  type        = string
}

variable "api_gateway_task_role_arn" {
  description = "ARN of API Gateway task role"
  type        = string
}

variable "event_ingest_task_role_arn" {
  description = "ARN of Event Ingest task role"
  type        = string
}

variable "event_processor_task_role_arn" {
  description = "ARN of Event Processor task role"
  type        = string
}

variable "ecr_repository_urls" {
  description = "Map of service names to ECR repository URLs"
  type        = map(string)
}

variable "image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table"
  type        = string
}

variable "sqs_queue_url" {
  description = "URL of the SQS queue"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic"
  type        = string
}

variable "api_gateway_target_group_arn" {
  description = "ARN of the API Gateway target group"
  type        = string
}

# Service Discovery
variable "api_gateway_service_registry_arn" {
  description = "ARN of API Gateway service discovery service"
  type        = string
}

variable "event_ingest_service_registry_arn" {
  description = "ARN of Event Ingest service discovery service"
  type        = string
}

variable "event_processor_service_registry_arn" {
  description = "ARN of Event Processor service discovery service"
  type        = string
}

variable "event_ingest_dns" {
  description = "DNS name for Event Ingest service"
  type        = string
}

variable "event_processor_dns" {
  description = "DNS name for Event Processor service"
  type        = string
}

# Task sizing
variable "api_gateway_cpu" {
  description = "CPU units for API Gateway (256, 512, 1024, 2048, 4096)"
  type        = number
  default     = 256
}

variable "api_gateway_memory" {
  description = "Memory for API Gateway in MB"
  type        = number
  default     = 512
}

variable "event_ingest_cpu" {
  description = "CPU units for Event Ingest"
  type        = number
  default     = 256
}

variable "event_ingest_memory" {
  description = "Memory for Event Ingest in MB"
  type        = number
  default     = 512
}

variable "event_processor_cpu" {
  description = "CPU units for Event Processor"
  type        = number
  default     = 256
}

variable "event_processor_memory" {
  description = "Memory for Event Processor in MB"
  type        = number
  default     = 512
}

# Desired counts
variable "api_gateway_desired_count" {
  description = "Desired number of API Gateway tasks"
  type        = number
  default     = 2
}

variable "event_ingest_desired_count" {
  description = "Desired number of Event Ingest tasks"
  type        = number
  default     = 2
}

variable "event_processor_desired_count" {
  description = "Desired number of Event Processor tasks"
  type        = number
  default     = 1
}

# Auto scaling
variable "enable_autoscaling" {
  description = "Enable auto scaling"
  type        = bool
  default     = true
}

variable "api_gateway_min_count" {
  description = "Minimum number of API Gateway tasks"
  type        = number
  default     = 1
}

variable "api_gateway_max_count" {
  description = "Maximum number of API Gateway tasks"
  type        = number
  default     = 4
}

variable "event_ingest_min_count" {
  description = "Minimum number of Event Ingest tasks"
  type        = number
  default     = 1
}

variable "event_ingest_max_count" {
  description = "Maximum number of Event Ingest tasks"
  type        = number
  default     = 4
}

variable "event_processor_min_count" {
  description = "Minimum number of Event Processor tasks"
  type        = number
  default     = 1
}

variable "event_processor_max_count" {
  description = "Maximum number of Event Processor tasks"
  type        = number
  default     = 2
}

# Other settings
variable "use_fargate_spot" {
  description = "Use Fargate Spot for cost savings"
  type        = bool
  default     = false
}

variable "enable_container_insights" {
  description = "Enable CloudWatch Container Insights"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
