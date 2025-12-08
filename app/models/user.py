# -*- coding: utf-8 -*-

from sqlalchemy import String, Boolean, DateTime, JSON, Column, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
import uuid
from typing import Optional, Dict, List, Any
from app.database.postgres import Base
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from enum import Enum

class User(Base):
    __tablename__ = "users" 
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # MFA 相关字段
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)  # 加密存储
    mfa_method = Column(String, default="totp")
    last_mfa_login = Column(DateTime, nullable=True)
    
    # Profile and preferences
    profile_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, default=dict)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # OAuth and social login
    oauth_accounts: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, default=dict)
   
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"
    

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
    

# # 租户模型（多租户隔离）
# class Tenant(Base):
#     __tablename__ = "tenants"
#     id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
#     name = Column(String(100), unique=True, nullable=False)
#     domain = Column(String(255), unique=True, nullable=True)  # 租户域名
#     is_active = Column(Boolean, default=True)

# # 多租户用户模型（核心）
# class User(SQLAlchemyBaseUserTableAsync, Base):
#     __tablename__ = "users"
#     # 核心字段（FastAPI-Users基础字段）：id, email, hashed_password, is_active, is_verified, is_superuser
#     # 自定义字段（企业级）
#     id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
#     username = Column(String(50), unique=True, nullable=False)
#     phone = Column(String(11), unique=True, nullable=True)
#     # 多租户关联
#     tenant_id = Column(PGUUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, default=settings.DEFAULT_TENANT_ID)
#     # 角色字段（精细化权限）
#     role = Column(String(20), default="user", comment="admin/operator/user/guest")
#     # 性能优化：索引
#     __table_args__ = (
#         Index("ix_users_tenant_id", "tenant_id"),
#         Index("ix_users_role", "role"),
#     )
