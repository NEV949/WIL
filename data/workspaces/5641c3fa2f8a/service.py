from datetime import datetime, time
from pydantic import BaseModel, Field
from typing import Union
import math

OFFICE_LAT = 12.9716
OFFICE_LNG = 77.5946
RADIUS_METERS = 100.0
MIN_TIME = time(6, 0, 0)
MAX_TIME = time(22, 0, 0)

class ValidationResult(BaseModel):
    valid: bool
    reason: str

def haversine(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """
    Calculate the great-circle distance between two points on the Earth's surface in meters.
    """
    R = 6371000  # Earth's radius in meters

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    dlat = lat2_rad - lat1_rad
    dlng = math.radians(lng2) - math.radians(lng1)

    a = (math.sin(dlat / 2) ** 2 +
         math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlng / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c

def validate_punch(employee_id: int, timestamp: datetime, lat: float, lng: float) -> dict:
    """
    Validate a time punch based on location and time.
    """
    # 1. Location validation
    distance = haversine(OFFICE_LAT, OFFICE_LNG, lat, lng)
    if distance > RADIUS_METERS:
        result = ValidationResult(valid=False, reason="Location is outside the allowed geofence")
        return result.model_dump()

    # 2. Time validation
    current_time = timestamp.time()
    if current_time < MIN_TIME or current_time > MAX_TIME:
        result = ValidationResult(valid=False, reason="Timestamp is outside the allowed window")
        return result.model_dump()

    # 3. Success
    result = ValidationResult(valid=True, reason="Punch accepted")
    return result.model_dump()
