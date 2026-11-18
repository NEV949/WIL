import sys

sys.path.insert(0, '/workspace')

import pytest
from datetime import datetime, timezone
from src.punch_validation.models import PunchEvent, ValidationResult
from src.punch_validation.service import validate_punch

def test_punch_outside_hours():
    # Punch within radius but at 23:30 local time (18:00 UTC) which is outside allowed window
    event = PunchEvent(
        employee_id="emp125",
        timestamp=datetime(2023, 1, 1, 18, 0, tzinfo=timezone.utc),  # 23:30 local
        lat=12.9716,
        lng=77.5946,
    )
    result: ValidationResult = validate_punch(event)
    assert result.valid is False
    assert result.reason is not None
    assert "outside allowed window" in result.reason
