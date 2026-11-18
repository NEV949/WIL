import sys

sys.path.insert(0, '/workspace')

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from src.punch_validation.models import PunchEvent

def test_strict_input_validation():
    # employee_id must be a string; passing an int should raise ValidationError due to strict mode
    with pytest.raises(ValidationError):
        PunchEvent(
            employee_id=12345,
            timestamp=datetime(2023, 1, 1, 6, 30, tzinfo=timezone.utc),
            lat=12.9716,
            lng=77.5946,
        )
