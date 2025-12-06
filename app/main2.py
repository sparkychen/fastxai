# -*- coding: utf-8 -*-

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import structlog
from app.security.sc_config import security_settings
from app.security.middleware import setup_security_middlewares
from app.security.rate_limit import setup_rate_limiting
from app.security.auth import auth_backend, fastapi_users
from app.database.postgres import init_db, close_db

# 初始化日志
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()

# 应用生命周期
@asynccontextmanager
async def app_lifespan(app: FastAPI):
    # 启动初始化
    await init_db()
    logger.info("FastAPI security initialized", environment=security_settings.ENVIRONMENT)
    yield
    # 关闭清理
    await close_db()

# 创建应用
app = FastAPI(
    title="Enterprise FastAPI",
    version="1.0.0",
    lifespan=app_lifespan,
    docs_url="/docs" if not security_settings.is_production else None,
    redoc_url="/redoc" if not security_settings.is_production else None,
)

# 集成安全中间件
setup_security_middlewares(app)

# 集成速率限制
limiter = setup_rate_limiting(app)

# 集成认证路由
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"]
)
app.include_router(
    fastapi_users.get_register_router(),
    prefix="/auth",
    tags=["auth"]
)
app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["auth"]
)

# 全局异常处理（安全增强）
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # 脱敏敏感信息
    detail = exc.detail
    if isinstance(detail, dict):
        from app.security.data_protection import data_masker
        detail = data_masker.mask_dict(detail)
    # 记录异常日志
    logger.error(
        "HTTP exception",
        status_code=exc.status_code,
        detail=detail,
        path=request.url.path,
        request_id=getattr(request.state, "request_id", "unknown")
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": detail, "request_id": getattr(request.state, "request_id", "unknown")}
    )

# 健康检查接口
@app.get("/health", tags=["system"])
async def health_check():
    return {
        "status": "healthy",
        "environment": security_settings.ENVIRONMENT,
        "security": {
            "https_enabled": security_settings.is_production,
            "rate_limit_enabled": security_settings.RATE_LIMIT_ENABLED,
            "mfa_required": security_settings.MFA_REQUIRED
        }
    }

# 示例：带权限的接口
from app.security.auth import require_roles, require_permission
from app.database.models.user import UserRole

@app.get("/admin/dashboard", tags=["admin"])
@limiter.limit(get_admin_rate_limit())  # 管理员限流
async def admin_dashboard(
    user: User = Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.AGENT_ADMIN]))
):
    return {"message": "Admin dashboard", "user_id": str(user.id)}

@app.post("/api/v1/knowledge", tags=["knowledge"])
@limiter.limit(get_default_rate_limit())
async def create_knowledge(
    request: Request,
    user: User = Depends(require_permission("knowledge:write"))
):
    # 业务逻辑
    return {"status": "success", "message": "Knowledge created"}
