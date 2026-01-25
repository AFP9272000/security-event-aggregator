#!/bin/bash
# LocalStack initialization script
# Creates required AWS resources for local development

set -e

echo "Initializing LocalStack resources..."

# Wait for LocalStack to be fully ready
sleep 5

# Create DynamoDB table
echo "Creating DynamoDB table..."
awslocal dynamodb create-table \
    --table-name security-events \
    --attribute-definitions \
        AttributeName=event_id,AttributeType=S \
    --key-schema \
        AttributeName=event_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1

echo "DynamoDB table created"

# Create SQS queue
echo "Creating SQS queue..."
awslocal sqs create-queue \
    --queue-name security-events-queue \
    --region us-east-1

echo "SQS queue created"

# Create SNS topic
echo "Creating SNS topic..."
awslocal sns create-topic \
    --name security-alerts \
    --region us-east-1

echo "SNS topic created"

# Create SNS subscription (email - will just log in LocalStack)
echo "Creating SNS subscription..."
awslocal sns subscribe \
    --topic-arn arn:aws:sns:us-east-1:000000000000:security-alerts \
    --protocol email \
    --notification-endpoint test@example.com \
    --region us-east-1

echo "SNS subscription created"

echo "LocalStack initialization complete!"

# List created resources
echo ""
echo "=== Created Resources ==="
echo "DynamoDB Tables:"
awslocal dynamodb list-tables --region us-east-1

echo ""
echo "SQS Queues:"
awslocal sqs list-queues --region us-east-1

echo ""
echo "SNS Topics:"
awslocal sns list-topics --region us-east-1
