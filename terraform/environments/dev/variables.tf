#------------------------------------------------------------------------------
# Security Event Aggregator - Dev Environment Variables
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# General
#------------------------------------------------------------------------------
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "sea"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

#------------------------------------------------------------------------------
# VPC Configuration
#------------------------------------------------------------------------------
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones"
  type        = number
  default     = 2
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use single NAT Gateway (cost savings)"
  type        = bool
  default     = true
}

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for AWS services"
  type        = bool
  default     = true
}

#------------------------------------------------------------------------------
# Database
#------------------------------------------------------------------------------
variable "dynamodb_billing_mode" {
  description = "DynamoDB billing mode"
  type        = string
  default     = "PAY_PER_REQUEST"
}

#------------------------------------------------------------------------------
# Notifications
#------------------------------------------------------------------------------
variable "alert_email" {
  description = "Email for security alerts"
  type        = string
  default     = ""
}

#------------------------------------------------------------------------------
# SSL/TLS
#------------------------------------------------------------------------------
variable "certificate_arn" {
  description = "ARN of ACM certificate for HTTPS"
  type        = string
  default     = ""
}

#------------------------------------------------------------------------------
# Container Configuration
#------------------------------------------------------------------------------
variable "image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

variable "api_gateway_cpu" {
  description = "CPU units for API Gateway"
  type        = number
  default     = 256
}

variable "api_gateway_memory" {
  description = "Memory for API Gateway (MB)"
  type        = number
  default     = 512
}

variable "event_ingest_cpu" {
  description = "CPU units for Event Ingest"
  type        = number
  default     = 256
}

variable "event_ingest_memory" {
  description = "Memory for Event Ingest (MB)"
  type        = number
  default     = 512
}

variable "event_processor_cpu" {
  description = "CPU units for Event Processor"
  type        = number
  default     = 256
}

variable "event_processor_memory" {
  description = "Memory for Event Processor (MB)"
  type        = number
  default     = 512
}

#------------------------------------------------------------------------------
# Scaling
#------------------------------------------------------------------------------
variable "api_gateway_desired_count" {
  description = "Desired count for API Gateway"
  type        = number
  default     = 1
}

variable "event_ingest_desired_count" {
  description = "Desired count for Event Ingest"
  type        = number
  default     = 1
}

variable "event_processor_desired_count" {
  description = "Desired count for Event Processor"
  type        = number
  default     = 1
}

variable "enable_autoscaling" {
  description = "Enable auto scaling"
  type        = bool
  default     = false
}

variable "use_fargate_spot" {
  description = "Use Fargate Spot (cost savings)"
  type        = bool
  default     = true
}

#------------------------------------------------------------------------------
# Observability
#------------------------------------------------------------------------------
variable "enable_container_insights" {
  description = "Enable Container Insights"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention days"
  type        = number
  default     = 14
}

#------------------------------------------------------------------------------
# CI/CD
#------------------------------------------------------------------------------
variable "enable_github_oidc" {
  description = "Enable GitHub OIDC for CI/CD"
  type        = bool
  default     = true
}

variable "github_repo" {
  description = "GitHub repository (owner/repo)"
  type        = string
  default     = ""
}
