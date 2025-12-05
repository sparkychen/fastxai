# -*- coding: utf-8 -*-

# app/models/user.py
from uuid import UUID, uuid4
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from fastapi_users.db import SQLAlchemyBaseUserTableAsync
from app.core.db import Base

# 租户模型（多租户隔离）
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(100), unique=True, nullable=False)
    domain = Column(String(255), unique=True, nullable=True)  # 租户域名
    is_active = Column(Boolean, default=True)

# 多租户用户模型（核心）
class User(SQLAlchemyBaseUserTableAsync, Base):
    __tablename__ = "users"
    # 核心字段（FastAPI-Users基础字段）：id, email, hashed_password, is_active, is_verified, is_superuser
    # 自定义字段（企业级）
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(50), unique=True, nullable=False)
    phone = Column(String(11), unique=True, nullable=True)
    # 多租户关联
    tenant_id = Column(PGUUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, default=settings.DEFAULT_TENANT_ID)
    # 角色字段（精细化权限）
    role = Column(String(20), default="user", comment="admin/operator/user/guest")
    # 性能优化：索引
    __table_args__ = (
        Index("ix_users_tenant_id", "tenant_id"),
        Index("ix_users_role", "role"),
    )
