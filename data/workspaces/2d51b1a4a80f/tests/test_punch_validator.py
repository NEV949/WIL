import sys

sys.path.insert(0, '/workspace')

from datetime import datetime
import pytz
from punch_validator import validate_punch

def test_validate_punch_timezone_conversion():
    # Constraint: Time comparisons must be performed in Asia/Kolkata regardless of input
    # 09:30 IST is 04:00 UTC
    utc_tz = pytz.utc
    ts_utc = utc_tz.localize(datetime(2023, 10, 1, 4, 0))
    result = validate_punch(employee_id=123, timestamp=ts_utc, lat=12.9716, lng=77.5946)
    assert result.valid is True
    assert result.reason == "Punch accepted"
