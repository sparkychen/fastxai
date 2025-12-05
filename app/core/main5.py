# -*- coding: utf-8 -*-

import structlog
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from app.core.config import settings
from app.core.db import startup_db, shutdown_db
from app.core.redis import get_redis_client, close_redis_client
from app.middleware.logging import StructuredLoggingMiddleware
from app.routers import auth, users
from app.metrics.auth import AUTH_COUNTER, AUTH_GAUGE, AUTH_HISTOGRAM

# 结构化日志配置
structlog.configure(
    processors=[
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger("main")

# ========== 创建FastAPI应用 ==========
app = FastAPI(
    title=settings.APP_NAME,
    docs_url=None if settings.ENV == "prod" else "/docs",
    redoc_url=None if settings.ENV == "prod" else "/redoc",
    openapi_url=None if settings.ENV == "prod" else "/openapi.json"
)

# ========== 中间件（生产级） ==========
# 1. CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 2. GZip压缩（提升传输性能）
app.add_middleware(GZipMiddleware, minimum_size=1000)
# 3. 结构化日志中间件
app.add_middleware(StructuredLoggingMiddleware)

# ========== 生命周期钩子 ==========
@app.on_event("startup")
async def on_startup():
    logger.info("Application starting up (env: %s)", settings.ENV)
    await startup_db()
    await get_redis_client()  # 初始化Redis
    # 暴露Prometheus指标
    Instrumentator().instrument(app).expose(app)

@app.on_event("shutdown")
async def on_shutdown():
    logger.info("Application shutting down")
    await shutdown_db()
    await close_redis_client()

# ========== 注册路由 ==========
app.include_router(auth.router)
app.include_router(users.router)

# ========== 健康检查接口（生产级必备） ==========
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

# ========== 测试接口（多租户+权限） ==========
from app.managers.user_manager import current_active_user
from app.models.user import User

def require_tenant_admin(tenant_id: str, user: User = Depends(current_active_user)):
    """自定义权限：租户管理员"""
    if user.tenant_id != tenant_id or user.role != "admin":
        raise HTTPException(status_code=403, detail="Tenant admin required")
    return user

@app.get(f"{settings.API_PREFIX}/tenant/{tenant_id}/dashboard")
async def tenant_dashboard(
    tenant_id: str,
    user: User = Depends(require_tenant_admin)
):
    """租户管理员专属接口"""
    return {
        "tenant_id": tenant_id,
        "user": user.username,
        "role": user.role
    }
