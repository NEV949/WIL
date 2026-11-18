import sys

sys.path.insert(0, '/workspace')

import pytest
from myservice import validate_punch, PunchRequest

def test_pydantic_input_validation_error():
    # Missing required field 'lat' should raise a validation error
    with pytest.raises(ValueError):
        request = PunchRequest(employee_id='E126', timestamp='2023-05-15T10:00:00+05:30', lng=77.5946)
        validate_punch(request)
