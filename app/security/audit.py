# -*- coding: utf-8 -*-

from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
from pydantic import BaseModel
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, String, DateTime, JSON, Text, Enum as SQLEnum

from ..config.database import Base
from .sc_config import security_settings

logger = structlog.get_logger()

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

class AuditService:
    """审计服务"""
    
    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.db_session = db_session
    
    async def log_event(self, event: AuditEvent):
        """记录审计事件"""
        try:
            # 结构化日志记录
            log_data = {
                "event_type": event.event_type,
                "severity": event.severity,
                "user_id": event.user_id,
                "user_ip": event.user_ip,
                "resource": f"{event.resource_type}/{event.resource_id}" 
                    if event.resource_type and event.resource_id 
                    else event.resource_type,
                "action": event.action,
                "request_id": event.request_id,
                "success": event.success,
            }
            
            # 根据严重级别记录日志
            if event.severity == AuditEventSeverity.CRITICAL:
                logger.critical("Security audit event", **log_data)
            elif event.severity == AuditEventSeverity.HIGH:
                logger.error("Security audit event", **log_data)
            elif event.severity == AuditEventSeverity.MEDIUM:
                logger.warning("Security audit event", **log_data)
            else:
                logger.info("Security audit event", **log_data)
            
            # 如果启用了审计日志且提供了数据库会话，则保存到数据库
            if security_settings.ENABLE_SECURITY_AUDIT and self.db_session:
                audit_log = AuditLog(
                    id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow(),
                    event_type=event.event_type,
                    severity=event.severity,
                    user_id=event.user_id,
                    user_email=event.user_email,
                    user_ip=event.user_ip,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    action=event.action,
                    request_method=event.request_method,
                    request_path=event.request_path,
                    request_id=event.request_id,
                    event_data=event.event_data,
                    metadata=event.metadata,
                    success="Y" if event.success else "N" if event.success is not None else None,
                    error_message=event.error_message,
                    hostname=os.uname().nodename if hasattr(os, 'uname') else "unknown",
                )
                
                self.db_session.add(audit_log)
                await self.db_session.commit()
        
        except Exception as e:
            logger.error("Failed to log audit event", error=str(e), event_type=event.event_type)
    
    async def log_login_attempt(
        self,
        user_id: Optional[str],
        user_email: Optional[str],
        user_ip: str,
        success: bool,
        request_id: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        """记录登录尝试"""
        event = AuditEvent(
            event_type=AuditEventType.USER_LOGIN,
            severity=AuditEventSeverity.HIGH if not success else AuditEventSeverity.LOW,
            user_id=user_id,
            user_email=user_email,
            user_ip=user_ip,
            action="login_attempt",
            request_id=request_id,
            success=success,
            error_message=error_message,
            event_data={
                "login_success": success,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        await self.log_event(event)
    
    async def log_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: Optional[str],
        action: str,
        user_ip: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        """记录数据访问"""
        event = AuditEvent(
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditEventSeverity.MEDIUM,
            user_id=user_id,
            user_ip=user_ip,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            request_id=request_id,
            success=True,
            event_data={
                "access_timestamp": datetime.utcnow().isoformat(),
                "access_type": action,
            }
        )
        await self.log_event(event)
    
    async def log_security_event(
        self,
        event_type: AuditEventType,
        severity: AuditEventSeverity,
        description: str,
        user_id: Optional[str] = None,
        user_ip: Optional[str] = None,
        request_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """记录安全事件"""
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            user_ip=user_ip,
            action="security_event",
            request_id=request_id,
            success=False,
            error_message=description,
            event_data=additional_data or {},
        )
        await self.log_event(event)

# FastAPI依赖项
async def get_audit_service(db: AsyncSession = Depends(get_db)) -> AuditService:
    """获取审计服务依赖项"""
    return AuditService(db)