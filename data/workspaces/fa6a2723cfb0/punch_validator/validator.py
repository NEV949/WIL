from datetime import datetime, time

from .models import Office, ValidateResponse

# Default office location
_OFFICE = Office(latitude=12.9716, longitude=77.5946, radius_meters=100.0)

# Valid time window (local office time)
_START_TIME = time(6, 0, 0)
_END_TIME = time(22, 0, 0)


def _haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points in meters."""
    from math import asin, cos, radians, sin, sqrt
    
    R = 6371000  # Earth's radius in meters
    
    lat1_r = radians(lat1)
    lat2_r = radians(lat2)
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    
    a = sin(dlat / 2) ** 2 + cos(lat1_r) * cos(lat2_r) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    
    return R * c


def validate_punch(
    employee_id: str,
    timestamp: str,
    lat: float,
    lng: float
) -> dict:
    """
    Validate employee punch location and time.
    
    Checks:
    1. Punch is within 100 meters of office (lat: 12.9716, lng: 77.5946)
    2. Timestamp falls between 06:00 and 22:00 local office time
    """
    # Parse timestamp
    try:
        dt = datetime.fromisoformat(timestamp)
    except (ValueError, TypeError):
        return {
            "valid": False,
            "reason": f"Invalid timestamp format: {timestamp}"
        }
    
    # Check time window
    punch_time = dt.time()
    if punch_time < _START_TIME or punch_time >= _END_TIME:
        return {
            "valid": False,
            "reason": f"Punch time {punch_time} is outside allowed window (06:00-22:00)"
        }
    
    # Check geofence
    distance = _haversine_meters(lat, lng, _OFFICE.latitude, _OFFICE.longitude)
    if distance > _OFFICE.radius_meters:
        return {
            "valid": False,
            "reason": f"Punch location is {distance:.1f} meters from office, exceeds {_OFFICE.radius_meters} meter limit"
        }
    
    return {
        "valid": True,
        "reason": "Punch is within office radius and time window"
    }