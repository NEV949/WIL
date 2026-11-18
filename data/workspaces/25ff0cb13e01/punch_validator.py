from datetime import datetime, time
from typing import Any, Dict

from pydantic import BaseModel, Field, validator

# ---------------------------------------------------
# Configuration
# ---------------------------------------------------

OFFICE_LAT: float = 12.9716
OFFICE_LNG: float = 77.5946
GEOFENCE_RADIUS_M: float = 100.0  # meters
ALLOWED_START: time = time(6, 0)   # 06:00
ALLOWED_END: time = time(22, 0)    # 22:00

# ---------------------------------------------------
# Pydantic models for input and output
# ---------------------------------------------------

class PunchRequest(BaseModel):
    employee_id: int
    timestamp: datetime
    lat: float
    lng: float

    @validator("timestamp")
    def _ensure_timezone(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone‑aware")
        return v

class PunchResult(BaseModel):
    valid: bool
    reason: str

# ---------------------------------------------------
# Helper functions
# ---------------------------------------------------

def _haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Calculate great‑circle distance between two points (in metres)."""
    import math

    r = 6371000.0  # Earth radius in metres
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)

    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c

def _is_within_geofence(lat: float, lng: float) -> bool:
    return _haversine_m(lat, lng, OFFICE_LAT, OFFICE_LNG) <= GEOFENCE_RADIUS_M

def _is_within_allowed_time(ts: datetime) -> bool:
    local_time = ts.time()
    return ALLOWED_START <= local_time < ALLOWED_END

# ---------------------------------------------------
# Public API
# ---------------------------------------------------

def validate_punch(employee_id: int, timestamp: datetime, lat: float, lng: float) -> Dict[str, Any]:
    """Validate a punch against location and time constraints.

    Returns a dictionary (compatible with ``PunchResult``) containing:
        - ``valid`` (bool): ``True`` if the punch meets all criteria.
        - ``reason`` (str): Human‑readable explanation.
    """
    request = PunchRequest(
        employee_id=employee_id,
        timestamp=timestamp,
        lat=lat,
        lng=lng,
    )

    if not _is_within_geofence(request.lat, request.lng):
        result = PunchResult(valid=False, reason="Location out of range")
        return result.model_dump()

    if not _is_within_allowed_time(request.timestamp):
        result = PunchResult(valid=False, reason="Time out of allowed range")
        return result.model_dump()

    result = PunchResult(valid=True, reason="Punch accepted")
    return result.model_dump()
