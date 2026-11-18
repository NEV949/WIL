from __future__ import annotations

from datetime import datetime, time
from math import radians, sin, cos, sqrt, atan2
from typing import Optional

from pydantic import BaseModel, Field, validator
from zoneinfo import ZoneInfo


class OfficeLocation(BaseModel):
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    geofence_radius_meters: float = Field(..., gt=0)
    timezone: str = "Asia/Kolkata"


class PunchRequest(BaseModel):
    employee_id: str
    timestamp: datetime
    lat: float = Field(..., ge=-90, le=90)
    lng: float = Field(..., ge=-180, le=180)

    @validator("timestamp")
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return v


class PunchValidationResult(BaseModel):
    valid: bool
    reason: Optional[str] = None


OFFICE = OfficeLocation(
    latitude=12.9716,
    longitude=77.5946,
    geofence_radius_meters=100.0,
    timezone="Asia/Kolkata",
)


def _haversine_distance(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Return distance in meters between two lat/lon points using the Haversine formula."""
    R = 6371000.0  # Earth radius in meters
    phi1, phi2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lng2 - lng1)

    a = sin(dphi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(dlambda / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c


def validate_punch(employee_id: str, timestamp: datetime, lat: float, lng: float) -> PunchValidationResult:
    """
    Validate a punch based on geofence (100 m) and allowed time window (06:00‑22:00)
    in the office's local timezone (Asia/Kolkata).

    Returns a PunchValidationResult indicating validity and an optional reason.
    """
    try:
        request = PunchRequest(employee_id=employee_id, timestamp=timestamp, lat=lat, lng=lng)
    except Exception as e:
        return PunchValidationResult(valid=False, reason=str(e))

    # Geofence check
    distance = _haversine_distance(request.lat, request.lng, OFFICE.latitude, OFFICE.longitude)
    in_geofence = distance <= OFFICE.geofence_radius_meters

    # Time window check
    local_dt = request.timestamp.astimezone(ZoneInfo(OFFICE.timezone))
    start = time(6, 0, 0)
    end = time(22, 0, 0)
    in_time_window = start <= local_dt.time() <= end

    if in_geofence and in_time_window:
        return PunchValidationResult(valid=True)

    reasons = []
    if not in_geofence:
        reasons.append(f"Geofence violation: {distance:.1f} m outside allowed {OFFICE.geofence_radius_meters} m radius.")
    if not in_time_window:
        reasons.append("Time window violation: punch outside 06:00‑22:00 office local time.")
    return PunchValidationResult(valid=False, reason="; ".join(reasons))
