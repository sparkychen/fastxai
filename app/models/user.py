# -*- coding: utf-8 -*-

from sqlalchemy import String, Boolean, DateTime, JSON, Column, Integer, Text, func
from datetime import datetime
import sqlalchemy as sa
import uuid
from typing import Optional, Dict, List, Any
from datetime import datetime
from pydantic import EmailStr, ConfigDict
from sqlmodel import SQLModel, Field, DateTime
from enum import Enum

class User(SQLModel, table=True):
    __tablename__ = "users" 
    __table_args__ = (
        sa.Table(
            __tablename__,
            SQLModel.metadata,
            comment='系统用户主表，存储用户核心身份信息',
            # 还可以在此添加其他参数，例如 schema='auth_schema'
        ))
    
    id: Optional[int] = Field(default=None, sa_column=Column(Integer, primary_key=True, comment="唯一标识（自增主键）"))
    email: EmailStr = Field(sa_column=Column(String(100),unique=True,index=True,nullable=False,comment="用户邮箱（唯一）"))
    # username: str = Field(unique=True, index=True, sa_column=Column(String(100), nullable=False, comment="用户名"))
    hashed_password: str = Field(sa_column=Column(String(255), nullable=False, comment="用户密码(加密)"))
    full_name: Optional[str] = Field(sa_column=Column(String(100), nullable=True, comment="用户全名"))
    is_active: bool = Field(sa_column=Column(Boolean, default=True, comment="是否是活跃状态"))
    is_superuser: bool = Field(sa_column=Column(Boolean, default=False, comment="是否是超级用户"))
    is_verified: bool = Field(sa_column=Column(Boolean, default=False, comment="是否已验证激活"))

    # MFA 相关字段
    mfa_enabled: bool = Field(sa_column=Column(Boolean, default=False, nullable=False, comment="是否强制启用MFA安全验证设置"))
    mfa_secret:str = Field(sa_column=Column(String(255), nullable=True, comment="MFA加密密码, mfa_enabled=True是不能为空"))
    mfa_method: str = Field(sa_column=Column(String(100), default="totp", nullable=False, comment="MFA method方法")) 
    last_mfa_login = Field(default=None,sa_column=Column(DateTime(timezone=True), nullable=True, comment="最近或最后一次通过MFA方式登录时间"))    
    
    # Profile and preferences
    profile_data: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_column=Column(JSON, comment="用户配置数据"))
    
    # Timestamps
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False, comment="创建时间"))
    updated_at: datetime = Field(sa_column=sa.Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
        onupdate=func.now(),
        comment="最后一次更新时间，自动设置更新数据库时间onupdate"
    ))
    last_login: datetime = Field(default=None,sa_column=Column(DateTime(timezone=True), nullable=True, comment="最近或会后一次登录时间"))
    
    # OAuth and social login
    oauth_accounts: Optional[Dict[str, Any]] = Field(default_factory=dict, sa_column=Column(JSON, comment="用户oauth账号信息"))
   
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"
    

class MFABackupCode(SQLModel):
    __tablename__ = "mfa_backup_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    code_hash = Column(String)  # 哈希后的备份代码
    used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class LoginAttempt(SQLModel):
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

class UserBase(SQLModel):
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserLogin(SQLModel):
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

class MFASetupRequest(SQLModel):
    method: MFAMethod

class MFASetupResponse(SQLModel):
    qr_code_url: str
    secret_key: str  # 仅用于演示，生产环境应加密
    backup_codes: List[str]

class MFAVerifyRequest(SQLModel):
    token: str = Field(..., min_length=6, max_length=6)
    method: MFAMethod

class Token(SQLModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    mfa_required: bool = False  # 标识是否需要 MFA 验证

class MFABackupVerify(SQLModel):
    backup_code: str = Field(..., min_length=8, max_length=8)
    

# # 租户模型（多租户隔离）
# class Tenant(SQLModel):
#     __tablename__ = "tenants"
#     id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
#     name = Column(String(100), unique=True, nullable=False)
#     domain = Column(String(255), unique=True, nullable=True)  # 租户域名
#     is_active = Column(Boolean, default=True)

# # 多租户用户模型（核心）
# class User(SQLModel):
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
