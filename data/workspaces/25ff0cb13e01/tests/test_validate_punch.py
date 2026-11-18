import sys

sys.path.insert(0, '/workspace')

def test_time_out_of_range():
    from datetime import datetime
    from mymodule import validate_punch
    # Within location range but time outside allowed window
    result = validate_punch(
        employee_id=125,
        timestamp=datetime(2023, 1, 1, 23, 0),
        lat=12.9716,
        lng=77.5946,
    )
    assert result == {"valid": False, "reason": "Time out of allowed range"}
