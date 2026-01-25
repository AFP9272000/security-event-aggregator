"""
Events API Routes

Provides REST endpoints for querying and retrieving security events.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime

from models import (
    SecurityEvent,
    EventSearchRequest,
    EventStats,
    EventSeverity,
    EventSource,
)
from utils import get_event_by_id, query_events, get_event_stats

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=List[dict])
async def list_events(
    limit: int = Query(default=100, le=1000, description="Maximum number of events to return"),
    offset: int = Query(default=0, ge=0, description="Number of events to skip"),
    severity: Optional[EventSeverity] = Query(default=None, description="Filter by severity"),
    source: Optional[EventSource] = Query(default=None, description="Filter by event source"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    start_time: Optional[datetime] = Query(default=None, description="Filter events after this time"),
    end_time: Optional[datetime] = Query(default=None, description="Filter events before this time"),
):
    """
    List security events with optional filters.
    
    Returns a list of normalized security events that match the specified criteria.
    Events are returned in reverse chronological order (newest first).
    """
    search = EventSearchRequest(
        limit=limit,
        offset=offset,
        severities=[severity] if severity else None,
        sources=[source] if source else None,
        event_types=[event_type] if event_type else None,
        start_time=start_time,
        end_time=end_time,
    )
    
    try:
        events = await query_events(search)
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying events: {str(e)}")


@router.get("/stats", response_model=EventStats)
async def get_statistics():
    """
    Get aggregated statistics about security events.
    
    Returns counts by severity, source, category, and other metrics
    useful for dashboard displays.
    """
    try:
        stats = await get_event_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting statistics: {str(e)}")


@router.get("/{event_id}")
async def get_event(event_id: str):
    """
    Get a specific security event by ID.
    
    Returns the full event details including raw event data.
    """
    try:
        event = await get_event_by_id(event_id)
        if not event:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
        return event
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving event: {str(e)}")


@router.post("/search", response_model=List[dict])
async def search_events(search: EventSearchRequest):
    """
    Advanced search for security events.
    
    Allows complex queries with multiple filters including:
    - Time ranges
    - Multiple severities
    - Multiple sources
    - Account IDs
    - Regions
    - Source IPs
    - Keyword search
    """
    try:
        events = await query_events(search)
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching events: {str(e)}")


@router.get("/severity/{severity}", response_model=List[dict])
async def get_events_by_severity(
    severity: EventSeverity,
    limit: int = Query(default=100, le=1000),
):
    """
    Get events filtered by severity level.
    
    Convenience endpoint for quickly filtering by severity.
    """
    search = EventSearchRequest(
        severities=[severity],
        limit=limit,
    )
    
    try:
        events = await query_events(search)
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying events: {str(e)}")


@router.get("/source/{source}", response_model=List[dict])
async def get_events_by_source(
    source: EventSource,
    limit: int = Query(default=100, le=1000),
):
    """
    Get events filtered by source.
    
    Convenience endpoint for viewing events from a specific source
    like CloudTrail or GuardDuty.
    """
    search = EventSearchRequest(
        sources=[source],
        limit=limit,
    )
    
    try:
        events = await query_events(search)
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying events: {str(e)}")
