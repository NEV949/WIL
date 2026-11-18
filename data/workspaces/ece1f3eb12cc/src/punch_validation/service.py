from __future__ import annotations

from datetime import datetime, time
from math import radians, sin, cos, sqrt, atan2
from zoneinfo import ZoneInfo
from typing import Final

from .models import OfficeLocation, PunchEvent, ValidationResult

# Fixed office configuration as required by the specification
DEFAULT_OFFICE: Final[OfficeLocation] = OfficeLocation(
    latitude=12.9716,
    longitude=77.5946,
    radius_meters=100.0,
    timezone="Asia/Kolkata",
    start_time=time(6, 0, 0),
    end_time=time(22, 0, 0),
)


def _haversine_distance_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Return the great‑circle distance between two points on Earth in metres.

    Implements the haversine formula using a mean Earth radius of 6 371 000 m.
    """
    radius_earth_m: Final[float] = 6_371_000.0
    phi1, phi2 = radians(lat1), radians(lat2)
    d_phi = radians(lat2 - lat1)
    d_lambda = radians(lng2 - lng1)
    a = sin(d_phi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(d_lambda / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return radius_earth_m * c


def _is_within_business_hours(ts_utc: datetime, office: OfficeLocation) -> bool:
    """Check whether *ts_utc* falls within the office's allowed local time window.

    The timestamp is first converted to the office's timezone.
    The start and end times are inclusive.
    """
    local_dt = ts_utc.astimezone(ZoneInfo(office.timezone))
    local_time = local_dt.time()
    if office.start_time <= office.end_time:
        return office.start_time <= local_time <= office.end_time
    # Edge case where the window spans midnight (not needed for current config)
    return local_time >= office.start_time or local_time <= office.end_time


def validate_punch(event: PunchEvent) -> ValidationResult:
    """Validate *event* against the fixed office geofence and business hours.

    Returns a :class:`ValidationResult` indicating success or the reason for failure.
    """
    # Geofence check
    distance = _haversine_distance_m(
        event.lat, event.lng, DEFAULT_OFFICE.latitude, DEFAULT_OFFICE.longitude
    )
    if distance > DEFAULT_OFFICE.radius_meters:
        return ValidationResult(
            valid=False,
            reason=f"Location {distance:.1f} m away exceeds allowed {DEFAULT_OFFICE.radius_meters:.0f} m radius.",
        )

    # Business‑hours check (timestamp is assumed to be UTC)
    if not _is_within_business_hours(event.timestamp, DEFAULT_OFFICE):
        local_dt = event.timestamp.astimezone(ZoneInfo(DEFAULT_OFFICE.timezone))
        return ValidationResult(
            valid=False,
            reason=f"Local time {local_dt.time().isoformat()} outside allowed window {DEFAULT_OFFICE.start_time.isoformat()}–{DEFAULT_OFFICE.end_time.isoformat()}.",
        )

    # All checks passed
    return ValidationResult(valid=True, reason=None)
