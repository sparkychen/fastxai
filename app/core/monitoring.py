# -*- coding: utf-8 -*-

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from enum import Enum
import redis.asyncio as redis
from prometheus_client import Counter, Histogram, Gauge
from app.core.config import settings
# from app.models.audit import AuditEventType, AuditEventSeverity
from app.services.audit_service import AuditService, AuditEventType, AuditEventSeverity
from pydantic import BaseModel
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

# Prometheus指标
SECURITY_EVENTS_TOTAL = Counter(
    'security_events_total',
    'Total number of security events',
    ['event_type', 'severity']
)

FAILED_LOGIN_ATTEMPTS = Counter(
    'failed_login_attempts_total',
    'Total number of failed login attempts'
)

SUCCESSFUL_LOGINS = Counter(
    'successful_logins_total',
    'Total number of successful logins'
)

API_KEY_VALIDATIONS = Counter(
    'api_key_validations_total',
    'Total number of API key validations',
    ['result']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint', 'status']
)

ACTIVE_SESSIONS = Gauge(
    'active_sessions_total',
    'Total number of active sessions'
)

class SecurityAlertType(str, Enum):
    """安全告警类型"""
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    MALICIOUS_IP = "malicious_ip"
    CONFIGURATION_CHANGE = "configuration_change"

class SecurityAlert(BaseModel):
    """安全告警模型"""
    alert_id: str
    alert_type: SecurityAlertType
    severity: AuditEventSeverity
    title: str
    description: str
    timestamp: datetime
    source_ip: Optional[str]
    user_id: Optional[str]
    resource: Optional[str]
    details: Dict[str, Any]
    acknowledged: bool = False
    resolved: bool = False

class SecurityMonitoringService:
    """安全监控服务"""
    
    def __init__(self, redis_client: redis.Redis, audit_service: AuditService):
        self.redis_client = redis_client
        self.audit_service = audit_service
        self.active_alerts: Dict[str, SecurityAlert] = {}
        self.suspicious_ips: Set[str] = set()
        
        # 监控配置
        self.config = {
            'brute_force_threshold': 10,  # 10分钟内10次失败登录
            'suspicious_activity_window': 300,  # 5分钟窗口
            'data_access_threshold': 100,  # 5分钟内100次数据访问
            'alert_cooldown': 300,  # 5分钟告警冷却
        }
    
    async def monitor_login_attempts(self, user_id: str, user_ip: str, success: bool):
        """监控登录尝试"""
        if success:
            SUCCESSFUL_LOGINS.inc()
            
            # 重置失败计数
            await self.reset_failed_attempts(user_id, user_ip)
        else:
            FAILED_LOGIN_ATTEMPTS.inc()
            
            # 记录失败尝试
            await self.record_failed_attempt(user_id, user_ip)
            
            # 检查是否达到暴力破解阈值
            if await self.check_brute_force_attempt(user_id, user_ip):
                await self.trigger_brute_force_alert(user_id, user_ip)
    
    async def record_failed_attempt(self, user_id: str, user_ip: str):
        """记录失败登录尝试"""
        now = datetime.utcnow()
        
        # 记录IP级别的失败尝试
        ip_key = f"failed_attempts:ip:{user_ip}"
        await self.redis_client.zadd(ip_key, {str(now.timestamp()): now.timestamp()})
        
        # 清理过期的记录（保留10分钟）
        ten_minutes_ago = (now - timedelta(minutes=10)).timestamp()
        await self.redis_client.zremrangebyscore(ip_key, 0, ten_minutes_ago)
        
        # 记录用户级别的失败尝试
        if user_id:
            user_key = f"failed_attempts:user:{user_id}"
            await self.redis_client.zadd(user_key, {str(now.timestamp()): now.timestamp()})
            await self.redis_client.zremrangebyscore(user_key, 0, ten_minutes_ago)
    
    async def check_brute_force_attempt(self, user_id: str, user_ip: str) -> bool:
        """检查是否达到暴力破解阈值"""
        now = datetime.utcnow()
        threshold = self.config['brute_force_threshold']
        
        # 检查IP级别的暴力破解
        ip_key = f"failed_attempts:ip:{user_ip}"
        ip_attempts = await self.redis_client.zcount(
            ip_key,
            (now - timedelta(minutes=10)).timestamp(),
            now.timestamp()
        )
        
        if ip_attempts >= threshold:
            logger.warning(
                "Brute force attempt detected by IP",
                ip=user_ip,
                attempts=ip_attempts
            )
            return True
        
        # 检查用户级别的暴力破解
        if user_id:
            user_key = f"failed_attempts:user:{user_id}"
            user_attempts = await self.redis_client.zcount(
                user_key,
                (now - timedelta(minutes=10)).timestamp(),
                now.timestamp()
            )
            
            if user_attempts >= threshold:
                logger.warning(
                    "Brute force attempt detected by user",
                    user_id=user_id,
                    attempts=user_attempts
                )
                return True        
        return False
    
    async def trigger_brute_force_alert(self, user_id: str, user_ip: str):
        """触发暴力破解告警"""
        alert_id = f"brute_force_{user_ip}_{datetime.utcnow().timestamp()}"
        
        alert = SecurityAlert(
            alert_id=alert_id,
            alert_type=SecurityAlertType.BRUTE_FORCE,
            severity=AuditEventSeverity.HIGH,
            title="Brute Force Attack Detected",
            description=f"Multiple failed login attempts from IP {user_ip}",
            timestamp=datetime.utcnow(),
            source_ip=user_ip,
            user_id=user_id,
            resource="authentication",
            details={
                "ip_address": user_ip,
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        
        # 保存告警
        self.active_alerts[alert_id] = alert
        
        # 记录审计事件
        await self.audit_service.log_security_event(
            event_type=AuditEventType.SECURITY_EVENT,
            severity=AuditEventSeverity.HIGH,
            description=f"Brute force attack detected from IP {user_ip}",
            user_id=user_id,
            user_ip=user_ip,
            additional_data={
                "alert_type": "brute_force",
                "alert_id": alert_id,
            }
        )
        
        # 触发告警动作（例如：发送邮件、Slack通知等）
        await self.execute_alert_actions(alert)
        
        logger.critical("Brute force alert triggered", ip=user_ip, user_id=user_id)
    
    async def reset_failed_attempts(self, user_id: str, user_ip: str):
        """重置失败尝试计数"""
        # 清理IP级别的失败尝试
        ip_key = f"failed_attempts:ip:{user_ip}"
        await self.redis_client.delete(ip_key)
        
        # 清理用户级别的失败尝试
        if user_id:
            user_key = f"failed_attempts:user:{user_id}"
            await self.redis_client.delete(user_key)
    
    async def monitor_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: Optional[str],
        action: str,
        user_ip: Optional[str] = None
    ):
        """监控数据访问模式"""
        now = datetime.utcnow()
        
        # 记录数据访问
        access_key = f"data_access:user:{user_id}:{resource_type}"
        await self.redis_client.zadd(
            access_key,
            {f"{action}_{now.timestamp()}": now.timestamp()}
        )
        
        # 清理过期的记录（保留5分钟）
        five_minutes_ago = (now - timedelta(minutes=5)).timestamp()
        await self.redis_client.zremrangebyscore(access_key, 0, five_minutes_ago)
        
        # 检查数据访问频率
        access_count = await self.redis_client.zcount(
            access_key,
            five_minutes_ago,
            now.timestamp()
        )
        
        if access_count > self.config['data_access_threshold']:
            await self.trigger_suspicious_activity_alert(
                user_id=user_id,
                activity_type="excessive_data_access",
                description=f"User accessed {resource_type} {access_count} times in 5 minutes",
                user_ip=user_ip,
                resource=f"{resource_type}/{resource_id}",
                details={
                    "access_count": access_count,
                    "resource_type": resource_type,
                    "time_window": "5 minutes",
                }
            )
    
    async def trigger_suspicious_activity_alert(
        self,
        user_id: str,
        activity_type: str,
        description: str,
        user_ip: Optional[str] = None,
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """触发可疑活动告警"""
        alert_id = f"suspicious_{user_id}_{datetime.utcnow().timestamp()}"
        
        alert = SecurityAlert(
            alert_id=alert_id,
            alert_type=SecurityAlertType.SUSPICIOUS_ACTIVITY,
            severity=AuditEventSeverity.MEDIUM,
            title="Suspicious Activity Detected",
            description=description,
            timestamp=datetime.utcnow(),
            source_ip=user_ip,
            user_id=user_id,
            resource=resource,
            details=details or {},
        )
        
        # 保存告警
        self.active_alerts[alert_id] = alert
        
        # 记录审计事件
        await self.audit_service.log_security_event(
            event_type=AuditEventType.SECURITY_EVENT,
            severity=AuditEventSeverity.MEDIUM,
            description=description,
            user_id=user_id,
            user_ip=user_ip,
            additional_data={
                "alert_type": "suspicious_activity",
                "activity_type": activity_type,
                "alert_id": alert_id,
                **details,
            }
        )
        
        logger.warning("Suspicious activity alert triggered", 
                      user_id=user_id, 
                      activity_type=activity_type)
    
    async def execute_alert_actions(self, alert: SecurityAlert):
        """执行告警动作"""
        # 根据告警严重级别执行不同动作
        actions = []
        
        if alert.severity in [AuditEventSeverity.HIGH, AuditEventSeverity.CRITICAL]:
            actions.append("notify_security_team")
            actions.append("block_ip_temporarily")
            actions.append("escalate_to_manager")
        
        elif alert.severity == AuditEventSeverity.MEDIUM:
            actions.append("notify_security_team")
            actions.append("log_for_review")
        
        # 执行动作
        for action in actions:
            await self._execute_alert_action(alert, action)
    
    async def _execute_alert_action(self, alert: SecurityAlert, action: str):
        """执行单个告警动作"""
        try:
            if action == "notify_security_team":
                # 发送邮件通知
                await self._send_security_email(alert)
            
            elif action == "block_ip_temporarily":
                # 临时封禁IP
                if alert.source_ip:
                    await self._block_ip_temporarily(alert.source_ip)
            
            elif action == "escalate_to_manager":
                # 上报给管理层
                await self._escalate_alert(alert)
            
            elif action == "log_for_review":
                # 记录供后续审查
                await self._log_for_review(alert)
        
        except Exception as e:
            logger.error(f"Failed to execute alert action {action}", 
                        error=str(e), 
                        alert_id=alert.alert_id)
    
    async def _send_security_email(self, alert: SecurityAlert):
        """发送安全邮件"""
        # 实现邮件发送逻辑
        # 可以使用SMTP、SendGrid、AWS SES等
        pass
    
    async def _block_ip_temporarily(self, ip_address: str, minutes: int = 30):
        """临时封禁IP"""
        block_key = f"ip_block:{ip_address}"
        await self.redis_client.setex(block_key, minutes * 60, "blocked")
        
        logger.info(f"IP {ip_address} blocked for {minutes} minutes")
    
    async def get_active_alerts(self, resolved: bool = False) -> List[SecurityAlert]:
        """获取活跃告警"""
        alerts = list(self.active_alerts.values())
        
        if not resolved:
            alerts = [alert for alert in alerts if not alert.resolved]
        
        return sorted(alerts, key=lambda x: x.timestamp, reverse=True)
    
    async def acknowledge_alert(self, alert_id: str, user_id: str):
        """确认告警"""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledged = True
            
            # 记录审计事件
            await self.audit_service.log_security_event(
                event_type=AuditEventType.SECURITY_EVENT,
                severity=AuditEventSeverity.LOW,
                description=f"Alert {alert_id} acknowledged by user {user_id}",
                user_id=user_id,
                additional_data={
                    "alert_id": alert_id,
                    "action": "acknowledged",
                }
            )
    
    async def resolve_alert(self, alert_id: str, user_id: str, resolution_notes: str):
        """解决告警"""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.resolved = True
            
            # 记录审计事件
            await self.audit_service.log_security_event(
                event_type=AuditEventType.SECURITY_EVENT,
                severity=AuditEventSeverity.LOW,
                description=f"Alert {alert_id} resolved by user {user_id}",
                user_id=user_id,
                additional_data={
                    "alert_id": alert_id,
                    "action": "resolved",
                    "resolution_notes": resolution_notes,
                }
            )
            
            logger.info(f"Alert {alert_id} resolved by user {user_id}")