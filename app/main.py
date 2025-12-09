# -*- coding: utf-8 -*-

import os
import sys
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import ORJSONResponse
from datetime import datetime
from fastapi.routing import APIRoute
from app.core.middlewares import SecurityMiddleware
from app.core.monitoring import SecurityMonitoringService
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from app.services.audit_service import AuditService #get_audit_service
from app.core.config import settings
from uuid_extensions import uuid7
from app.core.middlewares import StructuredLoggingMiddleware, AuditLogMiddleware
from app.database.postgres import startup_db, shutdown_db, get_auto_rw_db, auto_rw_separation
from app.database.redis import get_redis_client, close_redis_client
# from fastapi_structlog import init_logging, StructlogMiddleware, AccessLogMiddleware, CurrentScopeSetMiddleware
# from app.middleware.logging import RequestContextLoggingMiddleware
# from app.middleware.tracing import TracingMiddleware
from app.core.handlers import http_exception_handler, generic_exception_handler
from asgi_correlation_id import CorrelationIdMiddleware  # 需额外安装：pip install asgi-correlation-id
from prometheus_fastapi_instrumentator import Instrumentator
from starlette_prometheus import metrics, PrometheusMiddleware
from fastapi_bgtasks_dashboard import mount_bg_tasks_dashboard
from fastapi_profiler import PyInstrumentProfilerMiddleware
from starlette.staticfiles import StaticFiles
from app.models.user import User
from fastapi_users import FastAPIUsers
from app.services.user_service import auth_backend, get_user_manager
from typing import Any
import orjson
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)
# ========== 依赖：获取当前用户 ==========
current_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)


class CustomORJSONResponse(ORJSONResponse):
    def render(self, content: Any) -> bytes:
        return orjson.dumps(
            content,
            option=orjson.OPT_INDENT_2 | orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS | orjson.OPT_UTC_Z

        )

if sys.platform == "linux":
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# @auto_rw_separation
@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    logger.info(
        "Application start...",
        env=settings.ENV,
        log_level=settings.AUDIT_LOG_LEVEL,
        log_format=settings.AUDIT_LOG_FORMAT,
        async_log=settings.AUDIT_LOG_ASYNC,
    )
    
    if settings.ENV != "prod":
        logger.warning("注册的路由:")
        for route in app.router.routes:
            if isinstance(route, APIRoute):
                print(f"{route.methods}: path={route.path}, name={route.name}")

    if settings.SENTRY_DNS:
        from app.core.sentry import configure_sentry
        configure_sentry()

    # 启动
    logger.info("Starting security-enhanced application")

    await startup_db()
    
    # 初始化安全监控
    redis_client = await get_redis_client()
    app.state.redis_client = redis_client
    async with get_auto_rw_db() as db_session:
        audit_service = AuditService(db_session)
        security_monitoring = SecurityMonitoringService(redis_client, audit_service)        
        # 存储到应用状态
        app.state.security_monitoring = security_monitoring
        app.state.audit_service = audit_service
    
    logger.info("Security services initialized")
    
    yield
    
    await shutdown_db()
    # 关闭
    logger.info("Shutting down security services")
    await close_redis_client()

    logger.info("Application shutting down")
    # # 等待异步日志处理器刷新
    # if settings.LOG.ENABLE_ASYNC:
    #     from app.utils.async_logger import async_log_processor
    #     await async_log_processor.flush() 
    #     import time
    #     time.sleep(settings.LOG.ASYNC_FLUSH_INTERVAL + 1)

"""创建安全加固的FastAPI应用"""
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    debug=settings.DEBUG,
    openapi_url="/api/openapi.json" if settings.DEBUG else None, # 生产环境禁用
    docs_url="/docs" if settings.ENV != "prod" else None, # 生产环境禁用
    redoc_url="/redoc" if settings.ENV != "prod" else None, # 生产环境禁用
    default_response_class=CustomORJSONResponse,
)

app.mount("/static", app=StaticFiles(directory="app/web/static"), name="static")
app.mount("/ui", app=StaticFiles(directory="app/web/templates"), name="templates")
mount_bg_tasks_dashboard(app=app, mount_dashboard=True) 
app.add_middleware(PrometheusMiddleware)
app.add_middleware(PyInstrumentProfilerMiddleware, is_print_each_request=True)
app.add_route("/metrics", metrics)  
Instrumentator().instrument(app).expose(app, endpoint="/jjxxzx/metrics")
# FastAPIInstrumentor.instrument_app(app)
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
    allow_origins=settings.ALLOWED_ORIGINS,  # 生产环境严格限制
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
# app.add_middleware(RequestContextLoggingMiddleware)

# ========== 3. 注册异常处理器 ==========
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# 添加安全路由
# from app.security.api_keys import validate_api_key
from app.core.rbac import require_permission, Permission

# @app.get("/api/secure/status")
# async def secure_status(
#     api_key = Depends(validate_api_key)
# ):
#     """安全状态端点（需要API密钥）"""
#     return {
#         "status": "secure",
#         "timestamp": datetime.utcnow().isoformat(),
#         "api_key_id": api_key.key_id,
#     }

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
async def dbs_health_check():
    """健康检查接口（供K8s/监控使用）"""
    # 检查数据库
    db_healthy = True
    try:
        from app.database.postgres import get_db_manager
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

@app.get("/favicon.ico")
async def favicon():
    return CustomORJSONResponse(status_code=200)
    
 
