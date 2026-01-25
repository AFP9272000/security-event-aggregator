"""
Security Event Aggregator - Event Processor Service

This service processes security events from the SQS queue,
performs correlation analysis, calculates risk scores,
and triggers alerts for high-severity events.

Features:
- SQS message polling
- Event correlation and pattern detection
- Risk score calculation
- SNS alerting for high-severity events
- Health checks for load balancer
"""

import os
import json
import asyncio
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Dict, Any, List

import boto3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models import HealthResponse, EventStatus
from correlators import correlate_events, calculate_risk_score
from alerting import should_alert, send_event_alert, send_correlation_alert


# Service configuration
SERVICE_NAME = "event-processor"
SERVICE_VERSION = "1.0.0"

# AWS Configuration
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "security-events")
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
LOCALSTACK_ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT")

# Processing configuration
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "10"))
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "5"))
CORRELATION_WINDOW_MINUTES = int(os.environ.get("CORRELATION_WINDOW_MINUTES", "60"))

# Global state
processing_task = None
is_processing = False
stats = {
    "events_processed": 0,
    "alerts_sent": 0,
    "correlations_found": 0,
    "last_processed_at": None,
}


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


async def get_recent_events(minutes: int = 60) -> List[Dict[str, Any]]:
    """Get recent events from DynamoDB for correlation"""
    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(DYNAMODB_TABLE)
    
    # Calculate time threshold
    threshold = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    
    try:
        # Scan for recent events (in production, use a GSI)
        response = table.scan(
            FilterExpression="event_time >= :threshold",
            ExpressionAttributeValues={":threshold": threshold}
        )
        
        items = response.get("Items", [])
        
        # Convert Decimal to float for JSON compatibility
        for item in items:
            for key, value in item.items():
                if hasattr(value, "__float__"):
                    item[key] = float(value)
        
        return items
    except Exception as e:
        print(f"Error getting recent events: {e}")
        return []


async def update_event_status(event_id: str, status: str, risk_score: int = None, correlation_id: str = None):
    """Update event status in DynamoDB"""
    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(DYNAMODB_TABLE)
    
    try:
        update_expr = "SET #status = :status, processed_at = :processed_at"
        expr_values = {
            ":status": status,
            ":processed_at": datetime.utcnow().isoformat(),
        }
        expr_names = {"#status": "status"}
        
        if risk_score is not None:
            update_expr += ", risk_score = :risk_score"
            expr_values[":risk_score"] = risk_score
        
        if correlation_id:
            update_expr += ", correlation_id = :correlation_id"
            expr_values[":correlation_id"] = correlation_id
        
        table.update_item(
            Key={"event_id": event_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
            ExpressionAttributeNames=expr_names,
        )
    except Exception as e:
        print(f"Error updating event {event_id}: {e}")


async def process_message(message: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> bool:
    """
    Process a single SQS message.
    
    1. Parse the message to get event info
    2. Find the event in DynamoDB
    3. Run correlation analysis
    4. Calculate risk score
    5. Send alerts if needed
    6. Update event status
    """
    global stats
    
    try:
        # Parse message body
        body = json.loads(message.get("Body", "{}"))
        event_id = body.get("event_id")
        
        if not event_id:
            print("Message missing event_id, skipping")
            return False
        
        # Find the event in recent events
        event = next((e for e in recent_events if e.get("event_id") == event_id), None)
        
        if not event:
            # Event might be too old or not yet available
            print(f"Event {event_id} not found in recent events")
            return False
        
        # Run correlation analysis
        correlations = correlate_events(recent_events)
        stats["correlations_found"] = len(correlations)
        
        # Calculate risk score
        risk_score = calculate_risk_score(event, correlations)
        
        # Find correlations this event belongs to
        event_correlations = [
            c for c in correlations 
            if event_id in c.get("event_ids", [])
        ]
        
        # Determine correlation ID if applicable
        correlation_id = None
        if event_correlations:
            correlation_id = event_correlations[0].get("correlation_id")
        
        # Check if we should alert
        if should_alert(event, risk_score):
            await send_event_alert(event, risk_score, event_correlations)
            stats["alerts_sent"] += 1
        
        # Send correlation alerts for new patterns
        for correlation in correlations:
            # Only alert once per correlation
            if correlation.get("event_ids", [])[:1] == [event_id]:
                await send_correlation_alert(correlation)
        
        # Update event status
        await update_event_status(
            event_id,
            EventStatus.PROCESSED.value,
            risk_score,
            correlation_id
        )
        
        stats["events_processed"] += 1
        stats["last_processed_at"] = datetime.utcnow().isoformat()
        
        print(f"Processed event {event_id}, risk_score={risk_score}, correlations={len(event_correlations)}")
        return True
        
    except Exception as e:
        print(f"Error processing message: {e}")
        return False


async def poll_and_process():
    """Poll SQS for messages and process them"""
    global is_processing
    
    if not SQS_QUEUE_URL:
        print("SQS_QUEUE_URL not configured, processing disabled")
        return
    
    sqs = get_sqs_client()
    
    while is_processing:
        try:
            # Run blocking SQS call in thread pool to not block the event loop
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: sqs.receive_message(
                    QueueUrl=SQS_QUEUE_URL,
                    MaxNumberOfMessages=BATCH_SIZE,
                    WaitTimeSeconds=POLL_INTERVAL_SECONDS,
                    MessageAttributeNames=["All"],
                )
            )
            
            messages = response.get("Messages", [])
            
            if messages:
                print(f"Received {len(messages)} messages from SQS")
                
                # Get recent events for correlation
                recent_events = await get_recent_events(CORRELATION_WINDOW_MINUTES)
                
                # Process each message
                for message in messages:
                    success = await process_message(message, recent_events)
                    
                    # Delete message from queue if processed successfully
                    if success:
                        await loop.run_in_executor(
                            None,
                            lambda m=message: sqs.delete_message(
                                QueueUrl=SQS_QUEUE_URL,
                                ReceiptHandle=m["ReceiptHandle"]
                            )
                        )
            
        except Exception as e:
            print(f"Error in poll loop: {e}")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    global processing_task, is_processing
    
    print(f"Starting {SERVICE_NAME} v{SERVICE_VERSION}")
    print(f"SQS Queue: {SQS_QUEUE_URL}")
    print(f"SNS Topic: {SNS_TOPIC_ARN}")
    
    # Start processing task
    is_processing = True
    processing_task = asyncio.create_task(poll_and_process())
    
    yield
    
    # Stop processing task
    is_processing = False
    if processing_task:
        processing_task.cancel()
        try:
            await processing_task
        except asyncio.CancelledError:
            pass
    
    print(f"Shutting down {SERVICE_NAME}")


# Create FastAPI app
app = FastAPI(
    title="Security Event Aggregator - Event Processor",
    description="""
    Event processing service for the Security Event Aggregator system.
    
    Features:
    - Polls SQS for new events
    - Correlates events to detect attack patterns
    - Calculates risk scores
    - Sends alerts via SNS for high-severity events
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


@app.get("/", tags=["root"])
async def root():
    """Root endpoint - service information"""
    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "description": "Security Event Processor Service",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    """Health check endpoint"""
    dependencies = {}
    
    # Check DynamoDB
    try:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE)
        table.table_status
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
    
    # Check processing status
    dependencies["processing"] = "active" if is_processing else "inactive"
    
    all_healthy = all(
        status in ["healthy", "not configured", "active"]
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


@app.get("/stats", tags=["monitoring"])
async def get_stats():
    """Get processing statistics"""
    return {
        "service": SERVICE_NAME,
        "stats": stats,
        "config": {
            "batch_size": BATCH_SIZE,
            "poll_interval_seconds": POLL_INTERVAL_SECONDS,
            "correlation_window_minutes": CORRELATION_WINDOW_MINUTES,
        }
    }


@app.post("/process/trigger", tags=["processing"])
async def trigger_processing():
    """
    Manually trigger event processing.
    
    Useful for testing or catching up on events.
    """
    if not SQS_QUEUE_URL:
        raise HTTPException(status_code=400, detail="SQS_QUEUE_URL not configured")
    
    try:
        # Get recent events
        recent_events = await get_recent_events(CORRELATION_WINDOW_MINUTES)
        
        # Run correlation analysis
        correlations = correlate_events(recent_events)
        
        return {
            "status": "triggered",
            "recent_events_count": len(recent_events),
            "correlations_found": len(correlations),
            "correlations": correlations,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8002,
        reload=os.environ.get("DEBUG", "false").lower() == "true",
    )
