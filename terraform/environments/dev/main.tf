#------------------------------------------------------------------------------
# Security Event Aggregator - Dev Environment
# Main Terraform configuration that orchestrates all modules
#------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment to use S3 backend for state storage
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "security-event-aggregator/dev/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

#------------------------------------------------------------------------------
# Local Variables
#------------------------------------------------------------------------------
locals {
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

#------------------------------------------------------------------------------
# VPC Module
#------------------------------------------------------------------------------
module "vpc" {
  source = "../../modules/vpc"

  project_name         = var.project_name
  aws_region           = var.aws_region
  vpc_cidr             = var.vpc_cidr
  az_count             = var.az_count
  enable_nat_gateway   = var.enable_nat_gateway
  single_nat_gateway   = var.single_nat_gateway
  enable_vpc_endpoints = var.enable_vpc_endpoints

  tags = local.tags
}

#------------------------------------------------------------------------------
# ECR Module
#------------------------------------------------------------------------------
module "ecr" {
  source = "../../modules/ecr"

  project_name  = var.project_name
  service_names = ["api-gateway", "event-ingest", "event-processor"]
  scan_on_push  = true

  tags = local.tags
}

#------------------------------------------------------------------------------
# DynamoDB Module
#------------------------------------------------------------------------------
module "dynamodb" {
  source = "../../modules/dynamodb"

  project_name                  = var.project_name
  billing_mode                  = var.dynamodb_billing_mode
  enable_point_in_time_recovery = true

  tags = local.tags
}

#------------------------------------------------------------------------------
# SQS Module (includes SNS for alerts)
#------------------------------------------------------------------------------
module "sqs" {
  source = "../../modules/sqs"

  project_name = var.project_name
  enable_dlq   = true
  alert_email  = var.alert_email

  tags = local.tags
}

#------------------------------------------------------------------------------
# ALB Module
#------------------------------------------------------------------------------
module "alb" {
  source = "../../modules/alb"

  project_name      = var.project_name
  vpc_id            = module.vpc.vpc_id
  public_subnet_ids = module.vpc.public_subnet_ids
  certificate_arn   = var.certificate_arn

  tags = local.tags
}

#------------------------------------------------------------------------------
# Cloud Map Module (Service Discovery)
#------------------------------------------------------------------------------
module "cloudmap" {
  source = "../../modules/cloudmap"

  project_name   = var.project_name
  vpc_id         = module.vpc.vpc_id
  namespace_name = "${var.project_name}.local"

  tags = local.tags
}

#------------------------------------------------------------------------------
# IAM Module
#------------------------------------------------------------------------------
module "iam" {
  source = "../../modules/iam"

  project_name        = var.project_name
  dynamodb_table_arn  = module.dynamodb.table_arn
  sqs_queue_arn       = module.sqs.queue_arn
  sns_topic_arn       = module.sqs.sns_topic_arn
  ecr_repository_arns = values(module.ecr.repository_arns)
  enable_github_oidc  = var.enable_github_oidc
  github_repo         = var.github_repo

  tags = local.tags
}

#------------------------------------------------------------------------------
# ECS Module
#------------------------------------------------------------------------------
module "ecs" {
  source = "../../modules/ecs"

  project_name = var.project_name
  aws_region   = var.aws_region

  # Network
  private_subnet_ids    = module.vpc.private_subnet_ids
  ecs_security_group_id = module.alb.ecs_tasks_security_group_id

  # IAM
  ecs_execution_role_arn        = module.iam.ecs_execution_role_arn
  api_gateway_task_role_arn     = module.iam.api_gateway_task_role_arn
  event_ingest_task_role_arn    = module.iam.event_ingest_task_role_arn
  event_processor_task_role_arn = module.iam.event_processor_task_role_arn

  # Container images
  ecr_repository_urls = module.ecr.repository_urls
  image_tag           = var.image_tag

  # Data layer
  dynamodb_table_name = module.dynamodb.table_name
  sqs_queue_url       = module.sqs.queue_url
  sns_topic_arn       = module.sqs.sns_topic_arn

  # Load balancer
  api_gateway_target_group_arn = module.alb.api_gateway_target_group_arn

  # Service discovery
  api_gateway_service_registry_arn     = module.cloudmap.api_gateway_service_arn
  event_ingest_service_registry_arn    = module.cloudmap.event_ingest_service_arn
  event_processor_service_registry_arn = module.cloudmap.event_processor_service_arn
  event_ingest_dns                     = module.cloudmap.event_ingest_dns
  event_processor_dns                  = module.cloudmap.event_processor_dns

  # Task sizing (small for dev)
  api_gateway_cpu        = var.api_gateway_cpu
  api_gateway_memory     = var.api_gateway_memory
  event_ingest_cpu       = var.event_ingest_cpu
  event_ingest_memory    = var.event_ingest_memory
  event_processor_cpu    = var.event_processor_cpu
  event_processor_memory = var.event_processor_memory

  # Desired counts
  api_gateway_desired_count     = var.api_gateway_desired_count
  event_ingest_desired_count    = var.event_ingest_desired_count
  event_processor_desired_count = var.event_processor_desired_count

  # Auto scaling
  enable_autoscaling = var.enable_autoscaling
  use_fargate_spot   = var.use_fargate_spot

  # Observability
  enable_container_insights = var.enable_container_insights
  log_retention_days        = var.log_retention_days

  tags = local.tags
}
