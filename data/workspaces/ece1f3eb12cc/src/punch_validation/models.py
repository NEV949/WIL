from __future__ import annotations

from datetime import datetime, time
from typing import Optional

from pydantic import BaseModel, Field, StrictBool, StrictFloat, StrictStr


class OfficeLocation(BaseModel):
    """Configuration for the office geofence and working hours."""

    latitude: StrictFloat = Field(..., description="Office latitude in decimal degrees")
    longitude: StrictFloat = Field(..., description="Office longitude in decimal degrees")
    radius_meters: StrictFloat = Field(..., gt=0, description="Allowed radius around the office in metres")
    timezone: StrictStr = Field(..., description="IANA time‑zone identifier for the office location")
    start_time: time = Field(..., description="Inclusive start of allowed working hours (local time)")
    end_time: time = Field(..., description="Inclusive end of allowed working hours (local time)")

    model_config = {
        "strict": True,
        "populate_by_name": True,
    }


class PunchEvent(BaseModel):
    """Employee punch attempt with spatial and temporal data."""

    employee_id: StrictStr = Field(..., min_length=1)
    timestamp: datetime = Field(..., description="UTC timestamp of the punch")
    lat: StrictFloat = Field(..., description="Latitude of the punch location")
    lng: StrictFloat = Field(..., description="Longitude of the punch location")

    model_config = {"strict": True}


class ValidationResult(BaseModel):
    """Result of validating a punch event."""

    valid: StrictBool
    reason: Optional[StrictStr] = None

    model_config = {"strict": True}
