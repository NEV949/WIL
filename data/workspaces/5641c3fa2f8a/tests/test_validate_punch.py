import sys

sys.path.insert(0, '/workspace')

import pytest
from datetime import datetime
from service import validate_punch

def test_invalid_time():
    """Acceptance Criterion 3: reject punch when timestamp is outside allowed window."""
    # Time before 06:00
    result = validate_punch(
        employee_id=125,
        timestamp=datetime(2023, 5, 1, 5, 45, 0),
        lat=12.9716,
        lng=77.5946
    )
    assert result["valid"] is False
    assert "outside" in result["reason"].lower() or "time" in result["reason"].lower()
