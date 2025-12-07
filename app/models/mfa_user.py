# -*- coding: utf-8 -*-

from sqlalchemy import Boolean, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from enum import Enum

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # MFA 相关字段
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)  # 加密存储
    mfa_method = Column(String, default="totp")
    last_mfa_login = Column(DateTime, nullable=True)

class MFABackupCode(Base):
    __tablename__ = "mfa_backup_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    code_hash = Column(String)  # 哈希后的备份代码
    used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    ip_address = Column(String)
    user_agent = Column(Text)
    successful = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class MFAMethod(str, Enum):
    TOTP = "totp"
    EMAIL = "email"
    SMS = "sms"

class UserBase(BaseModel):
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    mfa_token: Optional[str] = None  # MFA 令牌

class UserResponse(UserBase):
    id: int
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class MFASetupRequest(BaseModel):
    method: MFAMethod

class MFASetupResponse(BaseModel):
    qr_code_url: str
    secret_key: str  # 仅用于演示，生产环境应加密
    backup_codes: List[str]

class MFAVerifyRequest(BaseModel):
    token: str = Field(..., min_length=6, max_length=6)
    method: MFAMethod

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    mfa_required: bool = False  # 标识是否需要 MFA 验证

class MFABackupVerify(BaseModel):
    backup_code: str = Field(..., min_length=8, max_length=8)