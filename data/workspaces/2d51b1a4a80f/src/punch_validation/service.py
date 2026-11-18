import math
from datetime import datetime, time
from typing import Annotated, Any, ClassVar, Literal
from pydantic import Field, plain_validator, ConfigDict, ValidationInfo
from pydantic.v1 import RootModel
from zoneinfo import ZoneInfo


# Office geolocation and constraints
OFFICE_LAT = 12.9716
OFFICE_LNG = 77.5946
RADIUS_METERS = 100.0

# Time window in Asia/Kolkata timezone
OFFICE_TZ = ZoneInfo("Asia/Kolkata")
START_TIME = time(6, 0, 0)
END_TIME = time(22, 0, 0)


class EmployeeId(RootModel[int]):
    """Strict non-negative integer identifier."""
    root: int

    @plain_validator(RootModel[int])
    @classmethod
    def _validate(cls, v: int) -> int:
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError("ID must be a strict integer.")
        if v < 0:
            raise ValueError("ID must be positive.")
        return v


class PunchTimestamp(RootModel[datetime]):
    """Strict datetime with timezone info."""
    root: datetime

    @plain_validator(RootModel[datetime])
    @classmethod
    def _validate(cls, v: datetime) -> datetime:
        if not isinstance(v, datetime) or v.tzinfo is None:
            raise ValueError("Timestamp must be a timezone-aware datetime.")
        return v


class GeoCoordinate(RootModel[dict[str, float]]):
    """
    Strict geolocation coordinates with validation on bounds.
    Structure: {'lat': float, 'lng': float}
    """
    root: dict[str, Any]

    @plain_validator(RootModel[dict[str, Any]])
    @classmethod
    def _validate(cls, v: dict[str, Any]) -> dict[str, float]:
        if not isinstance(v, dict):
            raise ValueError("Invalid coordinate object.")
        if set(v.keys()) != {'lat', 'lng'}:
            raise ValueError("Coordinate must have exactly 'lat' and 'lng'.")
        
        lat = v['lat']
        lng = v['lng']
        
        if not isinstance(lat, float) or isinstance(lat, bool):
            raise ValueError("'lat' must be a strict float.")
        if not isinstance(lng, float) or isinstance(lng, bool):
            raise ValueError("'lng' must be a strict float.")
            
        if lat < -90.0 or lat > 90.0:
            raise ValueError("Latitude must be in [-90, 90].")
        if lng < -180.0 or lng > 180.0:
            raise ValueError("Longitude must be in [-180, 180].")
            
        return {'lat': lat, 'lng': lng}


class ValidationResult(BaseModel):
    """Output payload for the validation service."""
    model_config = ConfigDict(strict=True)
    
    valid: bool
    reason: str


def _haversine(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """
    Computes the great-circle distance in meters between two geographic coordinates.
    Uses the standard Haversine formula.
    """
    R = 6371000.0  # Earth's radius in meters
    
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lng = math.radians(lng2 - lng1)
    
    a = (math.sin(delta_lat / 2) ** 2 +
         math.cos(lat1_rad) * math.cos(lat2_rad) *
         math.sin(delta_lng / 2) ** 2)
    c = 2 * math.asin(math.sqrt(a))
    
    return float(R * c)


def validate_punch(
    employee_id: int,
    timestamp: datetime,
    lat: float,
    lng: float
) -> ValidationResult:
    """
    Validates a punch record based on geolocation and time constraints.
    
    Raises:
        pydantic.ValidationError: If any input parameters are malformed.
    
    Returns:
        ValidationResult: The resulting status (valid/invalid) and reason.
    """
    # 1. Input Validation (Raises pydantic.ValidationError if malformed)
    EmployeeId(employee_id)
    ts = PunchTimestamp(timestamp)
    GeoCoordinate({'lat': lat, 'lng': lng})
    
    ts_ist = ts.root.astimezone(OFFICE_TZ)
    
    # 2. Time Validation
    current_time = ts_ist.time()
    if not (START_TIME <= current_time <= END_TIME):
        return ValidationResult(
            valid=False,
            reason="Timestamp outside permitted window"
        )
    
    # 3. Location Validation
    distance = _haversine(OFFICE_LAT, OFFICE_LNG, lat, lng)
    if distance > RADIUS_METERS:
        return ValidationResult(
            valid=False,
            reason="Location outside permitted radius"
        )
    
    # 4. Success
    return ValidationResult(
        valid=True,
        reason="Punch accepted"
    )
