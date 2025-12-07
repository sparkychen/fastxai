# -*- coding: utf-8 -*-

import os
import sys
import uvicorn
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request
from datetime import datetime
from app.security.middleware import SecurityMiddleware
from app.security.monitoring import SecurityMonitoringService
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from app.models.audit import AuditService, get_audit_service
from app.core.config import settings
from uuid_extensions import uuid7
from app.core.middlewares import StructuredLoggingMiddleware, AuditLogMiddleware
from app.config.database import get_db
# from fastapi_structlog import init_logging, StructlogMiddleware, AccessLogMiddleware, CurrentScopeSetMiddleware
# from app.middleware.logging import RequestContextLoggingMiddleware
# from app.middleware.tracing import TracingMiddleware
from app.core.handlers import http_exception_handler, generic_exception_handler
from asgi_correlation_id import CorrelationIdMiddleware  # 需额外安装：pip install asgi-correlation-id
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()
if settings.SENTRY_DNS:
    from app.core.sentry import configure_sentry
    configure_sentry()

if sys.platform == "linux" and os.name == "posix":
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())



@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    logger.info(
        "Application start...",
        env=settings.ENV,
        log_level=settings.LOG.LEVEL,
        log_format=settings.LOG.FORMAT,
        async_log=settings.LOG.ENABLE_ASYNC,
    )
    configure_sentry()
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

        # 健康检查
        # db_health = await check_db_health()
        # if db_health["status"] != "healthy":
        #     logger.error("DB health check failed", health=db_health)
        #     raise RuntimeError("Database initialization failed")
        # logger.info("App initialized successfully", db_health=db_health)
    
    logger.info("Security services initialized")
    
    yield
    
    # 关闭
    logger.info("Shutting down security services")
    await redis_client.close()

    logger.info("Application shutting down")
    # 等待异步日志处理器刷新
    if settings.LOG.ENABLE_ASYNC:
        from app.utils.async_logger import async_log_processor
        await async_log_processor.flush() 
        import time
        time.sleep(settings.LOG.ASYNC_FLUSH_INTERVAL + 1)

def create_secure_application() -> FastAPI:
    """创建安全加固的FastAPI应用"""
    app = FastAPI(
        title="FastXAI",
        version="2.0.0",
        lifespan=lifespan,
        openapi_url="/api/openapi.json" if settings.DEBUG else None, # 生产环境禁用
        docs_url="/docs" if settings.ENV != "prod" else None, # 生产环境禁用
        redoc_url="/redoc" if settings.ENV != "prod" else None, # 生产环境禁用
    )

    # app.add_middleware(CurrentScopeSetMiddleware)  # 1. 设置上下文
    app.add_middleware(
        CorrelationIdMiddleware,
        header_name="X-Request-ID",  # 可配置为任意头名称
        # 可选：自定义ID生成器
        generator=lambda: uuid7().hex,
    )    # 2. 生成请求ID
    app.add_middleware(StructuredLoggingMiddleware)        # 3. 将请求ID注入日志上下文
    app.add_middleware(AuditLogMiddleware)                 # 4. 记录访问日志（格式可自定义[citation:1]）

    # 1. CORS中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://your-domain.com"],  # 生产环境严格限制
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )
    # 2. GZip压缩（提升传输性能）
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    # 3. 结构化日志中间件
    app.add_middleware(StructuredLoggingMiddleware)
    
    # 设置安全中间件
    SecurityMiddleware.setup_security_middleware(app)

    # # 2. 分布式追踪中间件（先于日志中间件）
    # if settings.TRACING_ENABLE:
    #     app.add_middleware(TracingMiddleware)
    # 3. 请求上下文日志中间件（核心）
    app.add_middleware(RequestContextLoggingMiddleware)

    # ========== 3. 注册异常处理器 ==========
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)
    
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
    
    @app.get("/health", tags=["health"])
    async def health_check():
        """健康检查接口（供K8s/监控使用）"""
        # 检查数据库
        db_healthy = True
        try:
            from app.core.db import get_db_manager
            health = await get_db_manager().health_check()
            db_healthy = health["status"] == "healthy"
        except Exception:
            db_healthy = False
        # 检查Redis
        redis_healthy = True
        try:
            redis = await get_redis_client()
            await redis.ping()
        except Exception:
            redis_healthy = False
        # 整体状态
        overall_healthy = db_healthy and redis_healthy
        return {
            "status": "healthy" if overall_healthy else "unhealthy",
            "database": db_healthy,
            "redis": redis_healthy,
            "env": settings.ENV
        }
    
    def set_log_level(level: str):
        """动态设置日志级别（生产环境可API调整）"""
        level = level.upper()
        if level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            logger.setLevel(level)
            return True

        return False

    @app.get("/admin/log-level")
    async def set_log_level_api(level: str = "INFO"):
        if set_log_level(level):
            return {"status": "success", "level": level}
        return {"status": "error", "message": "Invalid log level"}
    
    @app.get("/users/me")
    async def read_users_me(request: Request, user: User = Depends(current_user)):
        # 企业级：使用structlog记录
        logger.info(
            "User profile requested",
            event="user_profile_request",
            user_id=user.id,
            username=user.username,
            ip_address=request.client.host,
            # 企业级：避免记录敏感信息
            # password=user.password,  # 不要记录
        )
        return user
        
    return app
    

# 创建应用
app = create_secure_application()

if __name__ == "__main__":
    
    
    # 生产环境配置
    uvicorn_config = {
        "host": settings.HOST,
        "port": settings.PORT,
        "reload": settings.DEBUG,
        "workers": 4,  # 多worker处理
        "proxy_headers": True,  # 支持代理头
        "forwarded_allow_ips": "*",  # 允许所有转发IP
        "timeout_keep_alive": 30,  # 连接保持超时
        "access_log": False,  # 禁用访问日志（使用结构化日志）
        "log_config": None,
    }
    
    uvicorn.run("main:app", **uvicorn_config)
