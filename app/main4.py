# -*- coding: utf-8 -*-
# doubao

from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import structlog
import asyncio
import uvloop
from app.core.config import audit_settings
from app.core.logging import configure_structlog
from app.core.audit_storage import audit_log_service
from app.core.audit_middleware import AuditLogMiddleware, audit_log

# 高性能事件循环
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# 初始化结构化日志
configure_structlog()
audit_logger = structlog.get_logger("app")

# ========== 应用生命周期 ==========
@asynccontextmanager
async def app_lifespan(app: FastAPI):
    # 启动：初始化审计日志服务
    audit_logger.info("Starting enterprise FastAPI app with audit log")
    await audit_log_service.init()
    yield
    # 关闭：清理审计日志服务
    audit_logger.info("Shutting down app")
    await audit_log_service.close()
    audit_logger.info("App shutdown completed")

# ========== 创建应用 ==========
app = FastAPI(
    title="Enterprise FastAPI Audit Log",
    version="1.0.0",
    lifespan=app_lifespan,
    docs_url="/docs" if audit_settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if audit_settings.ENVIRONMENT != "production" else None,
)

# ========== 中间件 ==========
# 1. CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.com"],  # 生产环境严格限制
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

# 2. 审计日志中间件（核心）
app.add_middleware(AuditLogMiddleware)

# ========== 健康检查接口 ==========
@app.get("/health", tags=["system"])
async def health_check():
    return {
        "status": "healthy",
        "app_name": audit_settings.APP_NAME,
        "environment": audit_settings.ENVIRONMENT,
        "audit_log_enabled": True,
    }

# ========== 示例业务接口（带手动审计日志） ==========
@app.post("/users", tags=["users"])
@audit_log(operation="create_user", resource_type="user")  # 手动审计日志
async def create_user(request: Request, username: str, email: str):
    """创建用户（示例：带手动审计日志）"""
    # 业务逻辑（示例）
    user_id = "123e4567-e89b-12d3-a456-426614174000"
    audit_logger.info("User created", user_id=user_id, username=username)
    return {"id": user_id, "username": username, "email": email}

@app.delete("/users/{user_id}", tags=["users"])
@audit_log(operation="delete_user", resource_type="user")
async def delete_user(request: Request, user_id: str):
    """删除用户（示例：带手动审计日志）"""
    # 业务逻辑（示例）
    audit_logger.info("User deleted", user_id=user_id)
    return {"status": "success", "user_id": user_id}
