"""
Security Event Aggregator - Event Ingest Service

This service receives security events from various sources,
normalizes them to a common schema, and queues them for processing.

Supported Sources:
- AWS CloudTrail
- AWS GuardDuty
- Generic security events

Features:
- Event normalization with MITRE ATT&CK mapping
- Async queueing via SQS
- DynamoDB persistence
- Health checks for load balancer
"""

import os
import json
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Dict, Any, List

import boto3
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models import SecurityEvent, EventSource, HealthResponse
from normalizers import normalize_cloudtrail_event, normalize_guardduty_finding


# Service configuration
SERVICE_NAME = "event-ingest"
SERVICE_VERSION = "1.0.0"

# AWS Configuration
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "security-events")
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL", "")
LOCALSTACK_ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT")


def get_dynamodb_client():
    """Get DynamoDB client"""
    if LOCALSTACK_ENDPOINT:
        return boto3.client(
            "dynamodb",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test"
        )
    return boto3.client("dynamodb", region_name=AWS_REGION)


def get_dynamodb_resource():
    """Get DynamoDB resource"""
    if LOCALSTACK_ENDPOINT:
        return boto3.resource(
            "dynamodb",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test"
        )
    return boto3.resource("dynamodb", region_name=AWS_REGION)


def get_sqs_client():
    """Get SQS client"""
    if LOCALSTACK_ENDPOINT:
        return boto3.client(
            "sqs",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test"
        )
    return boto3.client("sqs", region_name=AWS_REGION)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    print(f"Starting {SERVICE_NAME} v{SERVICE_VERSION}")
    print(f"DynamoDB Table: {DYNAMODB_TABLE}")
    print(f"SQS Queue: {SQS_QUEUE_URL}")
    yield
    print(f"Shutting down {SERVICE_NAME}")


# Create FastAPI app
app = FastAPI(
    title="Security Event Aggregator - Event Ingest",
    description="""
    Event ingestion service for the Security Event Aggregator system.
    
    Receives security events from multiple sources:
    - CloudTrail events
    - GuardDuty findings
    - Custom security events
    
    All events are normalized to a common schema with MITRE ATT&CK mapping.
    """,
    version=SERVICE_VERSION,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request models
class CloudTrailIngestionRequest(BaseModel):
    """Request body for CloudTrail event ingestion"""
    events: List[Dict[str, Any]]


class GuardDutyIngestionRequest(BaseModel):
    """Request body for GuardDuty finding ingestion"""
    findings: List[Dict[str, Any]]


class GenericEventRequest(BaseModel):
    """Request body for generic security events"""
    events: List[Dict[str, Any]]


class IngestionResponse(BaseModel):
    """Response for ingestion endpoints"""
    status: str
    events_received: int
    events_processed: int
    event_ids: List[str]


def serialize_event(event: SecurityEvent) -> Dict[str, Any]:
    """Serialize SecurityEvent for DynamoDB storage"""
    data = event.model_dump()
    
    # Convert datetime objects to ISO strings
    for key in ["event_time", "ingested_at", "processed_at"]:
        if data.get(key):
            if isinstance(data[key], datetime):
                data[key] = data[key].isoformat()
    
    # Convert enums to strings
    for key in ["source", "severity", "status"]:
        if data.get(key):
            data[key] = data[key].value if hasattr(data[key], "value") else str(data[key])
    
    # Handle nested objects
    if data.get("mitre_attack"):
        data["mitre_attack"] = {k: v for k, v in data["mitre_attack"].items() if v is not None}
    if data.get("aws_context"):
        data["aws_context"] = {k: v for k, v in data["aws_context"].items() if v is not None}
    if data.get("actor"):
        data["actor"] = {k: v for k, v in data["actor"].items() if v is not None}
    if data.get("network"):
        data["network"] = {k: v for k, v in data["network"].items() if v is not None}
    
    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}
    
    return data


async def store_event(event: SecurityEvent):
    """Store event in DynamoDB"""
    try:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE)
        
        item = serialize_event(event)
        table.put_item(Item=item)
        
        print(f"Stored event {event.event_id} in DynamoDB")
    except Exception as e:
        print(f"Error storing event {event.event_id}: {e}")
        raise


async def queue_event(event: SecurityEvent):
    """Queue event for processing via SQS"""
    if not SQS_QUEUE_URL:
        print("SQS_QUEUE_URL not configured, skipping queue")
        return
    
    try:
        sqs = get_sqs_client()
        
        message_body = json.dumps({
            "event_id": event.event_id,
            "source": event.source.value,
            "severity": event.severity.value,
            "event_type": event.event_type,
        })
        
        sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=message_body,
            MessageAttributes={
                "severity": {
                    "DataType": "String",
                    "StringValue": event.severity.value
                },
                "source": {
                    "DataType": "String",
                    "StringValue": event.source.value
                }
            }
        )
        
        print(f"Queued event {event.event_id} to SQS")
    except Exception as e:
        print(f"Error queueing event {event.event_id}: {e}")
        # Don't raise - queueing failure shouldn't fail ingestion


async def process_and_store(event: SecurityEvent):
    """Store event and queue for processing"""
    await store_event(event)
    await queue_event(event)


@app.get("/", tags=["root"])
async def root():
    """Root endpoint - service information"""
    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "description": "Security Event Ingest Service",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    """Health check endpoint"""
    dependencies = {}
    
    # Check DynamoDB
    try:
        dynamodb = get_dynamodb_client()
        dynamodb.describe_table(TableName=DYNAMODB_TABLE)
        dependencies["dynamodb"] = "healthy"
    except Exception as e:
        dependencies["dynamodb"] = f"unhealthy: {str(e)}"
    
    # Check SQS
    if SQS_QUEUE_URL:
        try:
            sqs = get_sqs_client()
            sqs.get_queue_attributes(
                QueueUrl=SQS_QUEUE_URL,
                AttributeNames=["QueueArn"]
            )
            dependencies["sqs"] = "healthy"
        except Exception as e:
            dependencies["sqs"] = f"unhealthy: {str(e)}"
    else:
        dependencies["sqs"] = "not configured"
    
    all_healthy = all(
        status == "healthy" or status == "not configured"
        for status in dependencies.values()
    )
    
    return HealthResponse(
        status="healthy" if all_healthy else "degraded",
        service=SERVICE_NAME,
        version=SERVICE_VERSION,
        timestamp=datetime.utcnow(),
        dependencies=dependencies,
    )


@app.get("/health/live", tags=["health"])
async def liveness_check():
    """Liveness probe"""
    return {"status": "alive"}


@app.post("/ingest/cloudtrail", response_model=IngestionResponse, tags=["ingest"])
async def ingest_cloudtrail(
    request: CloudTrailIngestionRequest,
    background_tasks: BackgroundTasks
):
    """
    Ingest CloudTrail events.
    
    Accepts an array of raw CloudTrail events and normalizes them
    to the common security event schema with MITRE ATT&CK mapping.
    """
    event_ids = []
    processed = 0
    
    for raw_event in request.events:
        try:
            normalized = normalize_cloudtrail_event(raw_event)
            background_tasks.add_task(process_and_store, normalized)
            event_ids.append(normalized.event_id)
            processed += 1
        except Exception as e:
            print(f"Error normalizing CloudTrail event: {e}")
    
    return IngestionResponse(
        status="accepted",
        events_received=len(request.events),
        events_processed=processed,
        event_ids=event_ids,
    )


@app.post("/ingest/guardduty", response_model=IngestionResponse, tags=["ingest"])
async def ingest_guardduty(
    request: GuardDutyIngestionRequest,
    background_tasks: BackgroundTasks
):
    """
    Ingest GuardDuty findings.
    
    Accepts an array of raw GuardDuty findings and normalizes them
    to the common security event schema with MITRE ATT&CK mapping.
    """
    event_ids = []
    processed = 0
    
    for raw_finding in request.findings:
        try:
            normalized = normalize_guardduty_finding(raw_finding)
            background_tasks.add_task(process_and_store, normalized)
            event_ids.append(normalized.event_id)
            processed += 1
        except Exception as e:
            print(f"Error normalizing GuardDuty finding: {e}")
    
    return IngestionResponse(
        status="accepted",
        events_received=len(request.findings),
        events_processed=processed,
        event_ids=event_ids,
    )


@app.post("/ingest/generic", response_model=IngestionResponse, tags=["ingest"])
async def ingest_generic(
    request: GenericEventRequest,
    background_tasks: BackgroundTasks
):
    """
    Ingest generic security events.
    
    Accepts pre-normalized events that conform to the SecurityEvent schema.
    Useful for custom security tools or third-party integrations.
    """
    event_ids = []
    processed = 0
    
    for raw_event in request.events:
        try:
            # Create SecurityEvent from raw data
            event = SecurityEvent(
                source=EventSource.CUSTOM,
                event_time=datetime.fromisoformat(raw_event.get("event_time", datetime.utcnow().isoformat())),
                event_type=raw_event.get("event_type", "custom"),
                event_category=raw_event.get("event_category", "custom"),
                title=raw_event.get("title", "Custom Security Event"),
                description=raw_event.get("description"),
                severity=raw_event.get("severity", "info"),
                raw_event=raw_event,
                tags=raw_event.get("tags", ["custom"]),
            )
            background_tasks.add_task(process_and_store, event)
            event_ids.append(event.event_id)
            processed += 1
        except Exception as e:
            print(f"Error processing generic event: {e}")
    
    return IngestionResponse(
        status="accepted",
        events_received=len(request.events),
        events_processed=processed,
        event_ids=event_ids,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=os.environ.get("DEBUG", "false").lower() == "true",
    )
