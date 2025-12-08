# -*- coding: utf-8 -*-

from sqlalchemy import String, Boolean, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
import uuid
from typing import Optional, Dict, Any
from app.database.postgres import Base

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
