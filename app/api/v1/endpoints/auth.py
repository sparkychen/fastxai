# -*- coding: utf-8 -*-

import structlog
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi_users import FastAPIUsers
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.models.user import User
from app.managers.user_manager import get_user_manager
from app.core.security import auth_backend
from app.core.config import settings
from app.core.redis import get_redis_client

logger = structlog.get_logger("auth_router")

# ========== 分布式速率限制（Redis） ==========
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL,
    storage_options={"password": settings.REDIS_PASSWORD.get_secret_value() if settings.REDIS_PASSWORD else None}
)

router = APIRouter(prefix=settings.API_PREFIX)
router.state.limiter = limiter
router.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ========== 初始化FastAPI-Users ==========
fastapi_users = FastAPIUsers[User, UUID](
    get_user_manager,
    [auth_backend]
)

# ========== 带速率限制的认证路由 ==========
# 登录接口（5次/分钟）
@router.post("/auth/jwt/login")
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login_with_rate_limit(request: Request):
    return await fastapi_users.get_auth_router(auth_backend).routes[0].endpoint(request)

# 注册接口（10次/小时）
@router.post("/auth/register")
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register_with_rate_limit(request: Request):
    return await fastapi_users.get_register_router().routes[0].endpoint(request)

# 密码重置请求（3次/小时）
@router.post("/auth/reset-password")
@limiter.limit(settings.RATE_LIMIT_RESET_PASSWORD)
async def reset_password_with_rate_limit(request: Request):
    return await fastapi_users.get_reset_password_router().routes[0].endpoint(request)

# ========== 注销接口（吊销Token） ==========
current_active_user = fastapi_users.current_user(active=True)

@router.post("/auth/logout")
async def logout(request: Request, user: User = Depends(current_active_user)):
    """注销接口（吊销Token）"""
    try:
        token = request.headers.get("Authorization").split(" ")[1]
        await revoke_token(token)
        return {"message": "Successfully logged out"}
    except Exception as e:
        logger.error("Logout failed", error=str(e))
        raise HTTPException(status_code=400, detail="Logout failed") from e

# ========== 其他内置路由 ==========
router.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"],
    exclude=["/login"]  # 排除默认登录，使用带速率限制的版本
)
router.include_router(fastapi_users.get_verify_router(), prefix="/auth", tags=["auth"])
router.include_router(fastapi_users.get_users_router(), prefix="/users", tags=["users"])
