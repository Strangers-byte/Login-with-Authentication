from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# User models
class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str

# class UserVerified(UserBase):
#     is_verified: bool

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        form_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str]
    token_type: str = "bearer"
    expires_in: int

class TokenPayload(BaseModel):
    sub: Optional[int]
    username: Optional[str]
    exp:Optional[int]

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# class RefreshTokenCreate(BaseModel):
#     user_id: int
#     token_hash: str
#     device_id: Optional[str] = None
#     expires_at: datetime

class PasswordResetRequest(BaseModel):
    email: str
    #reset_token: str

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class EmailValidationRequest(BaseModel):
    validation_token: str

class EmailValidationConfirm(BaseModel):
    validation_token: str
    validated_email: str


class PasswordResetResponse(BaseModel):
    message: str
    success: bool

class TokenVerificationResponse(BaseModel):
    valid: bool
    user_id: Optional[int] = None
    token: Optional[str] = None
    message: Optional[str] = None