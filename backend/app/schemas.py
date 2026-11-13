from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=150)
    full_name: str = Field(..., min_length=2, max_length=150)
    password: str = Field(..., min_length=8)

class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5)
    password: str = Field(..., min_length=1)

class TokenVerifyRequest(BaseModel):
    token: str

class RoleAssignRequest(BaseModel):
    role_names: List[str] = Field(..., min_length=1)

class CreateRoleRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    description: str = Field(..., min_length=5)
    permissions: List[str] = Field(default_factory=list)
