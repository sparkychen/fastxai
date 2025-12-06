# -*- coding: utf-8 -*-

import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, String, DateTime, JSON, Text, Enum as SQLEnum
import uuid
from ..config import Base
from app.core.config import settings


class AuditEventType(str, Enum):
    """审计事件类型"""
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    USER_CREATE = "USER_CREATE"
    USER_UPDATE = "USER_UPDATE"
    USER_DELETE = "USER_DELETE"
    ROLE_ASSIGN = "ROLE_ASSIGN"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    DATA_ACCESS = "DATA_ACCESS"
    DATA_MODIFY = "DATA_MODIFY"
    API_CALL = "API_CALL"
    SECURITY_EVENT = "SECURITY_EVENT"
    CONFIG_CHANGE = "CONFIG_CHANGE"

class AuditEventSeverity(str, Enum):
    """审计事件严重级别"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AuditLog(Base):
    """审计日志数据库模型"""
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(SQLEnum(AuditEventType), nullable=False, index=True)
    severity = Column(SQLEnum(AuditEventSeverity), default=AuditEventSeverity.LOW)
    
    # 用户信息
    user_id = Column(String(36), index=True, nullable=True)
    user_email = Column(String(255), nullable=True)
    user_ip = Column(String(45), nullable=True)  # 支持IPv6
    
    # 事件详情
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(36), nullable=True)
    action = Column(String(100), nullable=True)
    
    # 请求信息
    request_method = Column(String(10), nullable=True)
    request_path = Column(String(500), nullable=True)
    request_id = Column(String(36), nullable=True, index=True)
    
    # 事件数据
    event_data = Column(JSON, nullable=True)
    metadata = Column(JSON, nullable=True)
    
    # 结果
    success = Column(String(1), nullable=True)  # 'Y' or 'N'
    error_message = Column(Text, nullable=True)
    
    # 系统信息
    service_name = Column(String(100), default="fastapi-service")
    hostname = Column(String(255), nullable=True)

class AuditEvent(BaseModel):
    """审计事件数据模型"""
    event_type: AuditEventType
    severity: AuditEventSeverity = AuditEventSeverity.MEDIUM
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_ip: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    request_id: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None
