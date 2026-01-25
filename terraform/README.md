# Security Event Aggregator - Terraform Infrastructure

This directory contains the Terraform configuration to deploy the Security Event Aggregator to AWS ECS Fargate.

## Architecture

```
                                    ┌─────────────────┐
                                    │   Route 53      │
                                    │   (optional)    │
                                    └────────┬────────┘
                                             │
                                    ┌────────▼────────┐
                                    │       ALB       │
                                    │  (Public Subnet)│
                                    └────────┬────────┘
                                             │
              ┌──────────────────────────────┼──────────────────────────────┐
              │                              │                              │
     ┌────────▼────────┐           ┌────────▼────────┐           ┌────────▼────────┐
     │   API Gateway   │           │  Event Ingest   │           │ Event Processor │
     │    (Fargate)    │◄─────────►│    (Fargate)    │◄─────────►│    (Fargate)    │
     │   Port 8000     │           │   Port 8001     │           │   Port 8002     │
     └────────┬────────┘           └────────┬────────┘           └────────┬────────┘
              │                              │                              │
              │              ┌───────────────┼───────────────┐              │
              │              │               │               │              │
     ┌────────▼────────┐     │      ┌────────▼────────┐      │     ┌────────▼────────┐
     │    DynamoDB     │◄────┴─────►│      SQS        │◄─────┴────►│      SNS        │
     │   (Events)      │            │    (Queue)      │            │   (Alerts)      │
     └─────────────────┘            └─────────────────┘            └─────────────────┘
```

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Terraform** >= 1.5.0
3. **Docker** for building container images

## Quick Start

### 1. Initialize Terraform

```powershell
cd terraform/environments/dev
terraform init
```

### 2. Configure Variables

```powershell
# Copy the example file
Copy-Item terraform.tfvars.example terraform.tfvars

# Edit with your values
notepad terraform.tfvars
```

Key variables to set:
- `github_repo` - Your GitHub repository (e.g., "username/security-event-aggregator")
- `alert_email` - Email for security alerts

### 3. Deploy Infrastructure

```powershell
# Preview changes
terraform plan

# Apply changes
terraform apply
```

### 4. Build and Push Docker Images

After Terraform creates the ECR repositories, build and push the images:

```powershell
# Get the ECR login command
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build images
docker build -t sea/api-gateway:latest ./services/api-gateway
docker build -t sea/event-ingest:latest ./services/event-ingest
docker build -t sea/event-processor:latest ./services/event-processor

# Tag for ECR (use URLs from terraform output)
docker tag sea/api-gateway:latest <ecr-url>/sea/api-gateway:latest
docker tag sea/event-ingest:latest <ecr-url>/sea/event-ingest:latest
docker tag sea/event-processor:latest <ecr-url>/sea/event-processor:latest

# Push to ECR
docker push <ecr-url>/sea/api-gateway:latest
docker push <ecr-url>/sea/event-ingest:latest
docker push <ecr-url>/sea/event-processor:latest
```

### 5. Access the API

```powershell
# Get the ALB URL
terraform output api_url

# Test the API
curl http://<alb-dns-name>/health
curl http://<alb-dns-name>/events
```

## Module Structure

```
terraform/
├── environments/
│   └── dev/
│       ├── main.tf              # Main configuration
│       ├── variables.tf         # Variable definitions
│       ├── outputs.tf           # Output values
│       └── terraform.tfvars     # Your configuration
└── modules/
    ├── vpc/                     # VPC, subnets, NAT Gateway
    ├── ecr/                     # Container registries
    ├── ecs/                     # ECS cluster and services
    ├── alb/                     # Application Load Balancer
    ├── dynamodb/                # Events table
    ├── sqs/                     # Event queue and SNS alerts
    ├── iam/                     # IAM roles and policies
    └── cloudmap/                # Service discovery
```

## Cost Optimization (Dev Environment)

The dev configuration is optimized for cost:

| Resource | Strategy |
|----------|----------|
| NAT Gateway | Single NAT (not HA) |
| Fargate | Spot instances |
| DynamoDB | On-demand billing |
| ECS Tasks | Minimum counts (1 each) |
| Auto Scaling | Disabled |

**Estimated monthly cost**: ~$50-100/month (varies by usage)

## Security Features

- **Private Subnets**: All ECS tasks run in private subnets
- **Security Groups**: Least-privilege network rules
- **IAM Roles**: Separate task roles with minimal permissions
- **Encryption**: DynamoDB encryption at rest, SQS/SNS encryption
- **VPC Endpoints**: Private connectivity to AWS services
- **OIDC**: GitHub Actions uses OIDC (no long-lived credentials)

## Outputs

After deployment, Terraform provides these useful outputs:

| Output | Description |
|--------|-------------|
| `api_url` | URL to access the API |
| `ecr_repository_urls` | ECR URLs for pushing images |
| `ecs_cluster_name` | ECS cluster name |
| `dynamodb_table_name` | DynamoDB table name |
| `github_actions_role_arn` | IAM role ARN for CI/CD |
| `deployment_commands` | Commands to deploy images |

## Troubleshooting

### ECS Tasks Not Starting

```powershell
# Check ECS service events
aws ecs describe-services --cluster sea-cluster --services sea-api-gateway

# Check task logs
aws logs tail /ecs/sea/api-gateway --follow
```

### Container Health Check Failing

```powershell
# Check task status
aws ecs list-tasks --cluster sea-cluster --service-name sea-api-gateway
aws ecs describe-tasks --cluster sea-cluster --tasks <task-arn>
```

### Image Pull Errors

Ensure the ECS execution role has ECR permissions:
```powershell
# Verify ECR repository exists
aws ecr describe-repositories --repository-names sea/api-gateway
```

## Cleanup

To destroy all resources:

```powershell
terraform destroy
```

**Note**: This will delete all data in DynamoDB and SQS. Export any data you need first.
