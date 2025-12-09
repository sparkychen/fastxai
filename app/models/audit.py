# -*- coding: utf-8 -*-

import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
from sqlalchemy import Column, String, DateTime, JSON, Text, Integer,func, Enum as SQLEnum
from pydantic import EmailStr, ConfigDict
from sqlmodel import SQLModel, Field
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

class AuditLog(SQLModel,  table=True):
    """审计日志数据库模型"""
    __tablename__ = "audit_logs"
    __table_args__ = {'comment': '审计日志表'}
    
    id: Optional[int] = Field(default=None, sa_column=Column(Integer, primary_key=True, index=True, comment="唯一标识（自增主键）"))

    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False,index=True, comment="创建时间"))

    event_type:AuditEventType= Field(sa_column=Column(SQLEnum(AuditEventType),nullable=False,comment="审计事件类型"))
    severity:AuditEventSeverity = Field(sa_column=Column(SQLEnum(AuditEventSeverity),default=AuditEventSeverity.LOW, comment="审计事件严重级别"))
    
    # 用户信息
    user_id: int = Field(sa_column=Column(Integer, index=True, comment="备份用户ID，用户唯一标识"))
    email: EmailStr = Field(sa_column=Column(String(100),unique=True,index=True,nullable=True,comment="用户邮箱（唯一）"))
    user_ip: str = Field(sa_column=Column(String(50), index=False, comment="尝试或重试登录用户IP, 支持IPv6"))
    
    # 事件详情
    resource_type: str = Field(sa_column=Column(String(50), nullable=True, comment="资源类型"))
    resource_id: str = Field(sa_column=Column(String(50), nullable=True, comment="资源类型ID"))
    action: str = Field(sa_column=Column(String(50), nullable=True, comment="操作"))
    
    # 请求信息
    request_method: str = Field(sa_column=Column(String(50), nullable=True, comment="用户请求method"))
    request_path: str = Field(sa_column=Column(String(500), nullable=True, comment="用户请求路径path"))
    request_id: str = Field(sa_column=Column(String(50), nullable=True, comment="用户请求id"))
    
    # 事件数据
    event_data: Optional[Dict] = Field(default=None,sa_column=Column(JSON, nullable=True, comment="操作事件信息"))
    event_metadata: Optional[Dict] = Field(default=None,sa_column=Column(JSON, nullable=True, comment="操作事件信息元数据"))
    
    # 结果
    success: str = Field(sa_column=Column(String(1), nullable=True, comment="用户操作是否成功, Y:成功，N：失败")) # 'Y' or 'N'
    error_message: str = Field(sa_column=Column(Text, nullable=True, comment="用户操作是原因(信息)"))
    
    # 系统信息
    service_name: str = Field(sa_column=Column(String(100), default="fastapi-service", comment="审计服务service_name"))
    hostname: str = Field(sa_column=Column(String(255), nullable=True, comment="用户请求的hostname"))

class AuditEvent(SQLModel):
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
    event_: Optional[Dict[str, Any]] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None
