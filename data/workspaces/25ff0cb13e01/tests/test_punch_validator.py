from datetime import datetime, timezone, time
import math

import pytest

from punch_validator import (
    OFFICE_LAT,
    OFFICE_LNG,
    GEOFENCE_RADIUS_M,
    ALLOWED_START,
    ALLOWED_END,
    validate_punch,
    _haversine_m,
)


def _office_location() -> tuple[float, float]:
    return OFFICE_LAT, OFFICE_LNG


def _offset_location(lat: float, lng: float, north_m: float, east_m: float) -> tuple[float, float]:
    """Return a new lat/lng offset by the given metres north and east.
    Approximation works for small distances.
    """
    # Approximate meters per degree latitude/longitude at the Earth's surface
    meters_per_deg_lat = 111_320.0
    meters_per_deg_lng = 111_320.0 * math.cos(math.radians(lat))
    new_lat = lat + north_m / meters_per_deg_lat
    new_lng = lng + east_m / meters_per_deg_lng
    return new_lat, new_lng


def test_punch_accepted():
    ts = datetime(2023, 5, 17, 9, 15, tzinfo=timezone.utc)
    result = validate_punch(
        employee_id=1,
        timestamp=ts,
        lat=OFFICE_LAT,
        lng=OFFICE_LNG,
    )
    assert result == {"valid": True, "reason": "Punch accepted"}


def test_location_out_of_range():
    ts = datetime(2023, 5, 17, 10, 0, tzinfo=timezone.utc)
    # Move 200 m north (outside 100 m radius)
    lat, lng = _offset_location(OFFICE_LAT, OFFICE_LNG, north_m=200, east_m=0)
    result = validate_punch(
        employee_id=2,
        timestamp=ts,
        lat=lat,
        lng=lng,
    )
    assert result == {"valid": False, "reason": "Location out of range"}


def test_time_out_of_range():
    # Valid location but time 23:00 (outside allowed window)
    ts = datetime(2023, 5, 17, 23, 0, tzinfo=timezone.utc)
    result = validate_punch(
        employee_id=3,
        timestamp=ts,
        lat=OFFICE_LAT,
        lng=OFFICE_LNG,
    )
    assert result == {"valid": False, "reason": "Time out of allowed range"}
