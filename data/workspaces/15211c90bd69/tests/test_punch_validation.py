import sys

sys.path.insert(0, '/workspace')

import datetime
import pytest
from punch_validation import validate_punch

def test_time_outside_window():
    result = validate_punch(
        employee_id=3,
        timestamp=datetime.datetime(2023, 1, 1, 5, 45),
        lat=12.9716,
        lng=77.5946,
    )
    assert result["valid"] is False
    assert result["reason"] == "Time outside allowed window"
