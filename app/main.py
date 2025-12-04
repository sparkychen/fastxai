# -*- coding: utf-8 -*-

from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from datetime import datetime
import structlog
from app.security.middleware import SecurityMiddleware
from app.security.monitoring import SecurityMonitoringService
from app.security.audit import AuditService, get_audit_service
from app.config.database import get_db

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动
    logger.info("Starting security-enhanced application")
    
    # 初始化安全监控
    from redis.asyncio import Redis
    redis_client = Redis.from_url("redis://localhost:6379")
    
    async with get_db() as db_session:
        audit_service = AuditService(db_session)
        security_monitoring = SecurityMonitoringService(redis_client, audit_service)
        
        # 存储到应用状态
        app.state.security_monitoring = security_monitoring
        app.state.audit_service = audit_service
    
    logger.info("Security services initialized")
    
    yield
    
    # 关闭
    logger.info("Shutting down security services")
    await redis_client.close()

def create_secure_application() -> FastAPI:
    """创建安全加固的FastAPI应用"""
    app = FastAPI(
        title="Secure Enterprise API",
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/api/docs" if security_settings.DEBUG else None,
        redoc_url="/api/redoc" if security_settings.DEBUG else None,
        openapi_url="/api/openapi.json" if security_settings.DEBUG else None,
    )
    
    # 设置安全中间件
    SecurityMiddleware.setup_security_middleware(app)
    
    # 添加安全路由
    from app.security.api_keys import validate_api_key
    from app.security.rbac import require_permission, Permission
    
    @app.get("/api/secure/status")
    async def secure_status(
        api_key = Depends(validate_api_key)
    ):
        """安全状态端点（需要API密钥）"""
        return {
            "status": "secure",
            "timestamp": datetime.utcnow().isoformat(),
            "api_key_id": api_key.key_id,
        }
    
    @app.get("/api/secure/admin/metrics")
    async def admin_metrics(
        current_user = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """管理员指标端点（需要管理员权限）"""
        # 返回安全指标
        return {
            "active_sessions": ACTIVE_SESSIONS._value.get(),
            "security_events": SECURITY_EVENTS_TOTAL._metrics,
            "failed_logins": FAILED_LOGIN_ATTEMPTS._value.get(),
        }
    
    @app.get("/api/secure/alerts")
    async def get_security_alerts(
        current_user = Depends(require_permission(Permission.SYSTEM_AUDIT)),
        resolved: bool = False
    ):
        """获取安全告警（需要审计权限）"""
        monitoring: SecurityMonitoringService = app.state.security_monitoring
        alerts = await monitoring.get_active_alerts(resolved)
        
        return {
            "alerts": alerts,
            "count": len(alerts),
        }
    
    return app

# 创建应用
app = create_secure_application()

if __name__ == "__main__":
    import uvicorn
    
    # 生产环境配置
    uvicorn_config = {
        "host": security_settings.HOST,
        "port": security_settings.PORT,
        "reload": security_settings.DEBUG,
        "workers": 4,  # 多worker处理
        "proxy_headers": True,  # 支持代理头
        "forwarded_allow_ips": "*",  # 允许所有转发IP
        "timeout_keep_alive": 30,  # 连接保持超时
        "access_log": False,  # 禁用访问日志（使用结构化日志）
        "log_config": None,
    }
    
    uvicorn.run("main:app", **uvicorn_config)
