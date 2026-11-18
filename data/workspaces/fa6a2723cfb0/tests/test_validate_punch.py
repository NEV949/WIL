import sys

sys.path.insert(0, '/workspace')

import pytest
from datetime import datetime, time
from validate_punch import validate_punch, PunchInput, PunchResult

def test_invalid_punch_outside_time_window():
    # Correct location but time 23:00 (outside 06:00‑22:00 window)
    ts = datetime.combine(datetime.today(), time(hour=23, minute=0))
    inp = PunchInput(employee_id="E125", timestamp=ts, latitude=12.9716, longitude=77.5946)
    result: PunchResult = validate_punch(inp)
    assert result.valid is False
    assert "time" in result.reason.lower()
