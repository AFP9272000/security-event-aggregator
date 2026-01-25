"""
Security Event Aggregator - API Gateway Service

This service provides the external-facing REST API for querying
and retrieving security events from the aggregated event store.

Features:
- Query events with filters (severity, source, time range)
- Get event statistics for dashboards
- Search events with complex criteria
- Health checks for load balancer
"""

import os
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx

from models import HealthResponse
from routes import events_router
from utils import check_dynamodb_health


# Service configuration
SERVICE_NAME = "api-gateway"
SERVICE_VERSION = "1.0.0"

# Service discovery - other services
EVENT_INGEST_URL = os.environ.get("EVENT_INGEST_URL", "http://event-ingest:8001")
EVENT_PROCESSOR_URL = os.environ.get("EVENT_PROCESSOR_URL", "http://event-processor:8002")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    print(f"Starting {SERVICE_NAME} v{SERVICE_VERSION}")
    print(f"Event Ingest Service: {EVENT_INGEST_URL}")
    print(f"Event Processor Service: {EVENT_PROCESSOR_URL}")
    yield
    print(f"Shutting down {SERVICE_NAME}")


# Create FastAPI app
app = FastAPI(
    title="Security Event Aggregator - API Gateway",
    description="""
    External-facing API for the Security Event Aggregator system.
    
    This API provides endpoints to:
    - Query and search security events
    - Retrieve event statistics
    - Check system health
    
    Events are aggregated from multiple sources including:
    - AWS CloudTrail
    - AWS GuardDuty
    - Custom security tools
    """,
    version=SERVICE_VERSION,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(events_router)


@app.get("/", tags=["root"])
async def root():
    """Root endpoint - service information"""
    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "description": "Security Event Aggregator API Gateway",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    """
    Health check endpoint for load balancer.
    
    Checks connectivity to:
    - DynamoDB (event store)
    - Event Ingest Service
    - Event Processor Service
    """
    dependencies = {}
    
    # Check DynamoDB
    try:
        dynamodb_healthy = await check_dynamodb_health()
        dependencies["dynamodb"] = "healthy" if dynamodb_healthy else "unhealthy"
    except Exception as e:
        dependencies["dynamodb"] = f"unhealthy: {str(e)}"
    
    # Check Event Ingest Service
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{EVENT_INGEST_URL}/health")
            dependencies["event-ingest"] = "healthy" if response.status_code == 200 else "unhealthy"
    except Exception as e:
        dependencies["event-ingest"] = f"unreachable: {str(e)}"
    
    # Check Event Processor Service
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{EVENT_PROCESSOR_URL}/health")
            dependencies["event-processor"] = "healthy" if response.status_code == 200 else "unhealthy"
    except Exception as e:
        dependencies["event-processor"] = f"unreachable: {str(e)}"
    
    # Determine overall health
    all_healthy = all(
        status == "healthy" 
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
    """
    Liveness probe for Kubernetes/ECS.
    
    Simple check that the service is running.
    Does not check dependencies.
    """
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
async def readiness_check():
    """
    Readiness probe for Kubernetes/ECS.
    
    Checks if the service is ready to receive traffic.
    Verifies DynamoDB connectivity.
    """
    try:
        dynamodb_healthy = await check_dynamodb_health()
        if dynamodb_healthy:
            return {"status": "ready"}
        else:
            raise HTTPException(status_code=503, detail="DynamoDB not available")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Not ready: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=os.environ.get("DEBUG", "false").lower() == "true",
    )
