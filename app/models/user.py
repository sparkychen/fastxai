# -*- coding: utf-8 -*-

from sqlalchemy import String, Boolean, DateTime, JSON, Column, Integer, Text, func, Index, Enum as SqlEnum
from datetime import datetime
import sqlalchemy as sa
from pydantic import field_validator
from typing import Optional, Dict, List, Any
from pydantic import EmailStr, ConfigDict
from sqlmodel import SQLModel, Field
from fastapi_users import schemas
from enum import Enum
import re

# 手机号正则表达式（复用）
PHONE_REGEX = re.compile(r"^1[3-9]\d{9}$")

class UserRole(str, Enum):
    """用户角色（企业级RBAC基础）"""
    SUPERVISOR = "supervisor"
    ADMIN = "admin"
    OPERATOR = "operator"
    USER = "user"
    GUEST = "guest"

class UserStatus(str, Enum):
    """用户状态"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"

class UserRead(schemas.BaseUser[int]):
    """返回给前端的用户模型（脱敏）"""
    username: str
    phone: Optional[str]
    role: UserRole
    status: UserStatus
    full_name: Optional[str]

    # 脱敏手机号（企业级：中间4位隐藏）
    @field_validator("phone")
    def mask_phone(cls, v):
        if v:
            return f"{v[:3]}****{v[-4:]}"
        return v

class UserCreate(schemas.BaseUserCreate):
    """创建用户入参模型（验证规则）"""
    username: str = Field(min_length=8, max_length=20)
    phone: Optional[str] = Field(None)  # 手机号正则
    role: Optional[UserRole] = UserRole.USER
    full_name: Optional[str] = Field(max_length=50)

    # 用户名验证
    @field_validator("username")
    def validate_username(cls, v):
        if not v.isalnum():
            raise ValueError("用户名仅允许字母和数字")
        return v
    
    @field_validator("phone")
    def validate_phone(cls, v):
        if v is None:  # 允许空值，跳过验证
            return v
        if not PHONE_REGEX.match(v):
            raise ValueError("手机号格式错误（需为11位有效手机号）")
        return v

class UserUpdate(schemas.BaseUserUpdate):
    """更新用户入参模型"""
    username: Optional[str] = Field(min_length=8, max_length=20)
    phone: Optional[str] = Field(None)
    role: Optional[UserRole]
    status: Optional[UserStatus]
    full_name: Optional[str]

    @field_validator("phone")
    def validate_phone(cls, v):
        if v is None:  # 允许空值，跳过验证
            return v
        if not PHONE_REGEX.match(v):
            raise ValueError("手机号格式错误（需为11位有效手机号）")
        return v

class User(SQLModel, table=True):
    __tablename__ = "users" 
    __table_args__ = {'comment': '系统用户主表，存储用户核心身份信息'}
    
    id: Optional[int] = Field(default=None, sa_column=Column(Integer, primary_key=True, index=True, comment="唯一标识（自增主键）"))
    email: EmailStr = Field(sa_column=Column(String(100),unique=True,index=True,nullable=False,comment="用户邮箱（唯一）"))
    username: str = Field(sa_column=Column(String(100), unique=True, index=True, nullable=False, comment="用户名"))
    hashed_password: str = Field(sa_column=Column(String(255), nullable=False, comment="用户密码(加密)"))
    full_name: Optional[str] = Field(sa_column=Column(String(100), nullable=True, comment="用户全名"))
    phone: str = Field(sa_column=Column(String(11), unique=True, index=True, nullable=True, comment="用户手机号"))
    role: UserRole = Field(sa_column=Column(SqlEnum(UserRole), default=UserRole.USER, comment="用户角色role"))
    status: UserStatus = Field(sa_column=Column(SqlEnum(UserStatus), default=UserStatus.ACTIVE, comment="用户角色role"))
    is_active: bool = Field(sa_column=Column(Boolean, default=True, comment="是否是活跃状态"))
    is_superuser: bool = Field(sa_column=Column(Boolean, default=False, comment="是否是超级用户"))
    is_verified: bool = Field(sa_column=Column(Boolean, default=False, comment="是否已验证激活"))

    # MFA 相关字段
    mfa_enabled: bool = Field(sa_column=Column(Boolean, default=False, nullable=False, comment="是否强制启用MFA安全验证设置"))
    mfa_secret:str = Field(sa_column=Column(String(255), nullable=True, comment="MFA加密密码, mfa_enabled=True是不能为空"))
    mfa_method: str = Field(sa_column=Column(String(100), default="totp", nullable=False, comment="MFA method方法")) 
    last_mfa_login: datetime = Field(default=None,sa_column=Column(DateTime(timezone=True), nullable=True, comment="最近或最后一次通过MFA方式登录时间"))    
    
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
    
    __table_args__ = (
        Index("idx_user_role_status", "role", "status"),  # 复合索引（角色+状态）
    )

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"
    

class MFABackupCode(SQLModel, table=True):
    __tablename__ = "mfa_backup_codes"
    __table_args__ = {'comment': 'MFA(code)信息备份表'}
    
    id: Optional[int] = Field(default=None, sa_column=Column(Integer, primary_key=True, index=True, comment="唯一标识（自增主键）"))
    user_id: int = Field(sa_column=Column(Integer, index=True, comment="备份用户ID，用户唯一标识"))
    code_hash: str = Field(sa_column=Column(String(100), nullable=True, comment="哈希后的备份代码"))
    used: bool = Field(sa_column=Column(Boolean, default=False, comment="MFA(code)是否在用"))
    used_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=True, comment="使用时间"))
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False, comment="创建时间"))

class LoginAttempt(SQLModel, table=True):
    __tablename__ = "login_attempts"
    __table_args__ = {'comment': '尝试或重试登录表'}
    
    id: Optional[int] = Field(default=None, sa_column=Column(Integer, primary_key=True, index=True, comment="唯一标识（自增主键）"))
    user_id: int = Field(sa_column=Column(Integer, index=True, comment="尝试或重试登录用户ID，用户唯一标识"))
    ip_address:str = Field(sa_column=Column(String(20), index=False, comment="尝试或重试登录用户IP"))
    user_agent: str = Field(sa_column=Column(Text, index=False, comment="用户登录user_agent信息"))
    successful:bool = Field(sa_column=Column(Boolean, default=False, comment="是否尝试或重试登录成功"))
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False, comment="创建时间"))


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
