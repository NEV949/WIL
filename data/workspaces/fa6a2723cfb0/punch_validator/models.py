from pydantic import BaseModel


class Office(BaseModel):
    latitude: float
    longitude: float
    radius_meters: float = 100.0


class Punch(BaseModel):
    employee_id: str
    latitude: float
    longitude: float


class ValidateResponse(BaseModel):
    valid: bool
    reason: str