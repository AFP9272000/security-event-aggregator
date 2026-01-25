"""
Security Event Models

Defines the common schema for normalized security events.
All events from different sources (CloudTrail, GuardDuty, etc.) 
are normalized to this format.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid


class EventSeverity(str, Enum):
    """Severity levels aligned with common security frameworks"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventStatus(str, Enum):
    """Event processing status"""
    NEW = "new"
    PROCESSING = "processing"
    PROCESSED = "processed"
    CORRELATED = "correlated"
    ALERTED = "alerted"


class EventSource(str, Enum):
    """Supported event sources"""
    CLOUDTRAIL = "cloudtrail"
    GUARDDUTY = "guardduty"
    SECURITYHUB = "securityhub"
    CUSTOM = "custom"


class MitreAttackInfo(BaseModel):
    """MITRE ATT&CK framework mapping"""
    tactic: Optional[str] = Field(None, description="ATT&CK Tactic (e.g., 'Initial Access')")
    technique_id: Optional[str] = Field(None, description="Technique ID (e.g., 'T1078')")
    technique_name: Optional[str] = Field(None, description="Technique name")


class AWSContext(BaseModel):
    """AWS-specific context for events"""
    account_id: Optional[str] = None
    region: Optional[str] = None
    service: Optional[str] = None
    resource_arn: Optional[str] = None
    resource_type: Optional[str] = None


class ActorInfo(BaseModel):
    """Information about the actor/principal involved"""
    principal_id: Optional[str] = None
    principal_type: Optional[str] = None  # IAMUser, AssumedRole, AWSService, etc.
    arn: Optional[str] = None
    access_key_id: Optional[str] = None
    user_name: Optional[str] = None
    session_name: Optional[str] = None


class NetworkInfo(BaseModel):
    """Network-related information"""
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user_agent: Optional[str] = None


class SecurityEvent(BaseModel):
    """
    Normalized Security Event Schema
    
    This is the common format all security events are normalized to,
    regardless of their original source (CloudTrail, GuardDuty, etc.)
    """
    # Core identifiers
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: EventSource
    source_event_id: Optional[str] = Field(None, description="Original event ID from source")
    
    # Timestamps
    event_time: datetime = Field(description="When the event occurred")
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    processed_at: Optional[datetime] = None
    
    # Classification
    event_type: str = Field(description="Type of event (e.g., 'ConsoleLogin', 'UnauthorizedAccess')")
    event_category: str = Field(description="Category (e.g., 'authentication', 'data_access')")
    severity: EventSeverity = EventSeverity.INFO
    status: EventStatus = EventStatus.NEW
    
    # Descriptive
    title: str = Field(description="Human-readable event title")
    description: Optional[str] = None
    
    # Context
    aws_context: Optional[AWSContext] = None
    actor: Optional[ActorInfo] = None
    network: Optional[NetworkInfo] = None
    mitre_attack: Optional[MitreAttackInfo] = None
    
    # Correlation
    correlation_id: Optional[str] = Field(None, description="Links related events")
    related_event_ids: List[str] = Field(default_factory=list)
    
    # Raw data
    raw_event: Optional[Dict[str, Any]] = Field(None, description="Original event data")
    
    # Tags and metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class EventSearchRequest(BaseModel):
    """Search request for querying events"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sources: Optional[List[EventSource]] = None
    severities: Optional[List[EventSeverity]] = None
    event_types: Optional[List[str]] = None
    account_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    source_ips: Optional[List[str]] = None
    keywords: Optional[str] = None
    limit: int = Field(default=100, le=1000)
    offset: int = 0


class EventStats(BaseModel):
    """Statistics about security events"""
    total_events: int = 0
    events_by_severity: Dict[str, int] = Field(default_factory=dict)
    events_by_source: Dict[str, int] = Field(default_factory=dict)
    events_by_category: Dict[str, int] = Field(default_factory=dict)
    events_last_24h: int = 0
    critical_events_last_24h: int = 0
    top_event_types: List[Dict[str, Any]] = Field(default_factory=list)
    top_source_ips: List[Dict[str, Any]] = Field(default_factory=list)


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    service: str
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    dependencies: Dict[str, str] = Field(default_factory=dict)
