# 🛡️ Security Event Aggregator

A cloud-native microservices platform for aggregating, correlating, and alerting on AWS security events. Built with Python/FastAPI, deployed on ECS Fargate with full CI/CD automation.

[![CI/CD Pipeline](https://github.com/AFP9272000/security-event-aggregator/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/AFP9272000/security-event-aggregator/actions/workflows/ci-cd.yml)
[![Terraform](https://github.com/AFP9272000/security-event-aggregator/actions/workflows/terraform.yml/badge.svg)](https://github.com/AFP9272000/security-event-aggregator/actions/workflows/terraform.yml)

## 🎯 Overview

Security Event Aggregator (SEA) processes security events from multiple AWS sources, normalizes them into a common format, detects attack patterns through correlation rules, and generates real-time alerts. This project demonstrates enterprise-grade DevSecOps practices including containerized microservices, infrastructure as code, and automated CI/CD pipelines.

### Key Features

- **Multi-Source Ingestion**: CloudTrail, GuardDuty, and generic security events
- **MITRE ATT&CK Mapping**: 45+ technique mappings for threat classification
- **Real-Time Correlation**: Detect brute force, privilege escalation, data exfiltration patterns
- **Risk Scoring**: Quantifiable 0-100 risk scores for prioritization
- **Automated Alerting**: SNS notifications for critical security events
- **Full Observability**: CloudWatch dashboards, alarms, and log insights

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AWS Cloud                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    ┌──────────────┐                                                         │
│    │   Route 53   │ (Optional)                                              │
│    └──────┬───────┘                                                         │
│           │                                                                  │
│    ┌──────▼───────┐      ┌─────────────────────────────────────────────┐   │
│    │     ALB      │      │            VPC (10.0.0.0/16)                 │   │
│    │  (Public)    │      │  ┌─────────────────────────────────────────┐│   │
│    └──────┬───────┘      │  │         Private Subnets                 ││   │
│           │              │  │                                          ││   │
│           │              │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐   ││   │
│           └──────────────┼──┼─►│   API   │ │  Event  │ │  Event  │   ││   │
│                          │  │  │ Gateway │ │ Ingest  │ │Processor│   ││   │
│                          │  │  │ :8000   │ │ :8001   │ │ :8002   │   ││   │
│                          │  │  └────┬────┘ └────┬────┘ └────┬────┘   ││   │
│                          │  │       │           │           │        ││   │
│                          │  │       │    Cloud Map Service Discovery ││   │
│                          │  └───────┼───────────┼───────────┼────────┘│   │
│                          └──────────┼───────────┼───────────┼─────────┘   │
│                                     │           │           │              │
│    ┌────────────────────────────────┼───────────┼───────────┼────────────┐│
│    │                                ▼           ▼           ▼            ││
│    │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             ││
│    │  │  DynamoDB   │◄───│     SQS     │◄───│     SNS     │             ││
│    │  │  (Events)   │    │   (Queue)   │    │  (Alerts)   │             ││
│    │  └─────────────┘    └─────────────┘    └─────────────┘             ││
│    │                         Data Layer                                  ││
│    └─────────────────────────────────────────────────────────────────────┘│
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Microservices

| Service | Port | Responsibility |
|---------|------|----------------|
| **API Gateway** | 8000 | REST API for querying events, stats, and search |
| **Event Ingest** | 8001 | Receives and normalizes security events |
| **Event Processor** | 8002 | Correlation engine, risk scoring, alerting |

## 🔐 Security Features

### MITRE ATT&CK Mappings

The system maps security events to MITRE ATT&CK techniques:

| Tactic | Example Techniques |
|--------|-------------------|
| Initial Access | T1078 (Valid Accounts) |
| Persistence | T1136.003 (Create Cloud Account) |
| Privilege Escalation | T1548 (Abuse Elevation Control) |
| Defense Evasion | T1562.008 (Disable Cloud Logs) |
| Credential Access | T1528 (Steal Application Access Token) |
| Discovery | T1580 (Cloud Infrastructure Discovery) |
| Exfiltration | T1530 (Data from Cloud Storage) |
| Impact | T1485 (Data Destruction) |

### Correlation Rules

| Rule | Description | Severity |
|------|-------------|----------|
| **Brute Force** | ≥5 failed logins in 15 min | HIGH |
| **Privilege Escalation** | Login → Create access key/user in 60 min | CRITICAL |
| **Data Exfiltration** | ≥50 S3 GetObject in 30 min | HIGH |
| **Logging Tampering** | StopLogging, DeleteTrail events | CRITICAL |
| **Reconnaissance** | ≥20 List/Describe calls in 10 min | MEDIUM |

### Risk Scoring

Events receive a 0-100 risk score based on:
- Base severity (Critical=80, High=60, Medium=40, Low=20)
- +20 per correlation match
- +10 for MITRE ATT&CK mapping
- +30 for root account activity

## 🚀 Quick Start

### Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.5.0
- Docker Desktop
- Git

### Local Development

```bash
# Clone the repository
git clone https://github.com/AFP9272000/security-event-aggregator.git
cd security-event-aggregator

# Start with Docker Compose (uses LocalStack)
docker-compose up -d

# Wait for services to be healthy
sleep 30

# Test the API
curl http://localhost:8000/health
curl http://localhost:8000/events/stats

# Run the test script
python test_services.py
```

### Deploy to AWS

```bash
# Navigate to Terraform
cd terraform/environments/dev

# Configure your variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your settings

# Deploy
terraform init
terraform plan
terraform apply

# Get the API URL
terraform output api_url
```

## 📡 API Reference

### Events API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/events` | GET | List events with filters |
| `/events/stats` | GET | Aggregated statistics |
| `/events/{id}` | GET | Get specific event |
| `/events/search` | POST | Advanced search |
| `/events/severity/{level}` | GET | Filter by severity |
| `/events/source/{source}` | GET | Filter by source |

### Ingestion API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ingest/cloudtrail` | POST | Ingest CloudTrail events |
| `/ingest/guardduty` | POST | Ingest GuardDuty findings |
| `/ingest/generic` | POST | Ingest generic events |

### Example: Ingest CloudTrail Event

```bash
curl -X POST http://localhost:8001/ingest/cloudtrail \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "evt-123",
    "event_time": "2025-01-25T12:00:00Z",
    "event_source": "signin.amazonaws.com",
    "event_name": "ConsoleLogin",
    "aws_region": "us-east-1",
    "source_ip": "1.2.3.4",
    "user_identity": {
      "type": "IAMUser",
      "userName": "admin"
    },
    "response_elements": {
      "ConsoleLogin": "Success"
    }
  }'
```

## 🏭 Infrastructure

### Terraform Modules

| Module | Resources |
|--------|-----------|
| `vpc` | VPC, subnets, NAT Gateway, VPC endpoints |
| `ecr` | Container registries with lifecycle policies |
| `ecs` | Fargate cluster, task definitions, services |
| `alb` | Application Load Balancer, target groups |
| `dynamodb` | Events table with GSIs |
| `sqs` | Event queue, dead-letter queue |
| `iam` | Task roles, GitHub OIDC |
| `cloudmap` | Service discovery namespace |
| `monitoring` | CloudWatch dashboards, alarms |

### Cost Estimate (Dev Environment)

| Resource | Monthly Cost |
|----------|-------------|
| NAT Gateway | ~$32 |
| ALB | ~$16 |
| Fargate (3 tasks, Spot) | ~$10-15 |
| DynamoDB (on-demand) | ~$1-5 |
| VPC Endpoints | ~$7-14 |
| CloudWatch | ~$5 |
| **Total** | **~$70-85/month** |

## 🔄 CI/CD Pipeline

The GitHub Actions pipeline includes:

```
Push to main
    │
    ├─► Security Scan (Trivy + Checkov)
    │
    ├─► Build & Test (parallel x3 services)
    │
    ├─► Push to ECR
    │
    ├─► Deploy to ECS
    │
    └─► Integration Tests
```

### Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci-cd.yml` | Push to main | Full pipeline |
| `terraform.yml` | Changes to `terraform/` | Infrastructure updates |
| `manual-deploy.yml` | Manual | Deploy specific services |

### Required Secrets

| Secret | Description |
|--------|-------------|
| `AWS_ACCOUNT_ID` | Your 12-digit AWS account ID |

## 📊 Monitoring

### CloudWatch Dashboard

Access via: `https://console.aws.amazon.com/cloudwatch/home#dashboards:name=sea-dashboard`

Includes:
- ECS CPU/Memory utilization
- Running task counts
- ALB request metrics and latency
- DynamoDB read/write capacity
- SQS queue depth
- Security event logs

### Alarms

| Alarm | Threshold | Action |
|-------|-----------|--------|
| High CPU | >80% for 10 min | SNS alert |
| 5XX Errors | >10 in 5 min | SNS alert |
| High Latency | >2s avg | SNS alert |
| Queue Backup | >100 messages | SNS alert |
| Critical Events | Any | SNS alert |

## 📁 Project Structure

```
security-event-aggregator/
├── .github/
│   └── workflows/
│       ├── ci-cd.yml           # Main CI/CD pipeline
│       ├── terraform.yml       # Infrastructure CI
│       └── manual-deploy.yml   # Manual deployment
├── services/
│   ├── api-gateway/            # REST API service
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── src/
│   │       ├── main.py
│   │       ├── routes/
│   │       ├── models/
│   │       └── utils/
│   ├── event-ingest/           # Ingestion service
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── src/
│   │       ├── main.py
│   │       ├── normalizers/    # CloudTrail, GuardDuty
│   │       └── models/
│   └── event-processor/        # Processing service
│       ├── Dockerfile
│       ├── requirements.txt
│       └── src/
│           ├── main.py
│           ├── correlators/    # Attack pattern detection
│           ├── alerting/       # SNS notifications
│           └── models/
├── terraform/
│   ├── environments/
│   │   └── dev/
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   └── modules/
│       ├── vpc/
│       ├── ecr/
│       ├── ecs/
│       ├── alb/
│       ├── dynamodb/
│       ├── sqs/
│       ├── iam/
│       ├── cloudmap/
│       └── monitoring/
├── docker-compose.yml          # Local development
├── test_services.py            # Integration tests
└── README.md
```

## 🛠️ Technologies

| Category | Technologies |
|----------|-------------|
| **Languages** | Python 3.11 |
| **Frameworks** | FastAPI, Pydantic, Boto3 |
| **Containers** | Docker, ECS Fargate |
| **Infrastructure** | Terraform, VPC, ALB |
| **Data** | DynamoDB, SQS, SNS |
| **CI/CD** | GitHub Actions, OIDC |
| **Security** | Trivy, Checkov, IAM |
| **Monitoring** | CloudWatch, Container Insights |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Addison Plunkett**
- GitHub: [@AFP9272000](https://github.com/AFP9272000)
- LinkedIn: [Addison Plunkett](https://www.linkedin.com/in/addison-plunkett/)

---

*Built as a portfolio project demonstrating cloud security engineering and DevSecOps practices.*
