from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


OfficeCoordinates = (12.9716, 77.5946)
MAX_METER_DISTANCE = 100.0
TIME_START = (6, 0)
TIME_END = (22, 0)


class PunchRequest(BaseModel):
    employee_id: int = Field(..., gt=0)
    timestamp: datetime = Field(...)
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)


class ValidationResult(BaseModel):
    valid: bool
    reason: str = Field(..., min_length=1)


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points in km."""
    from math import asin, cos, radians, sin, sqrt

    earth_radius_km = 6371.0
    d_lat = radians(lat2 - lat1)
    d_lon = radians(lon2 - lon1)
    a = sin(d_lat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(d_lon / 2) ** 2
    c = 2 * asin(min(1.0, sqrt(a)))
    return c * earth_radius_km


def _validate_location(request: PunchRequest) -> str | None:
    off_lat, off_lng = OfficeCoordinates
    dist_m = haversine(request.latitude, request.longitude, off_lat, off_lng) * 1000.0
    if dist_m > MAX_METER_DISTANCE:
        return "Location out of range"
    return None


def _validate_time(request: PunchRequest) -> str | None:
    cur_hour, cur_min = (request.timestamp.hour, request.timestamp.minute)
    start_hour, start_min = TIME_START
    end_hour, end_min = TIME_END
    
    # Normalize time into minutes since midnight for robust comparison
    cur_minutes = cur_hour * 60 + cur_min
    start_minutes = start_hour * 60 + start_min
    end_minutes = end_hour * 60 + end_min
    
    if not (start_minutes <= cur_minutes <= end_minutes):
        return "Time outside allowed window"
    return None


def validate_punch(request: PunchRequest) -> ValidationResult:
    """Validate a geofenced punch request."""
    location_err = _validate_location(request)
    if location_err:
        return ValidationResult(valid=False, reason=location_err)
    
    time_err = _validate_time(request)
    if time_err:
        return ValidationResult(valid=False, reason=time_err)
    
    return ValidationResult(valid=True, reason="Punch accepted")
