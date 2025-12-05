# -*- coding: utf-8 -*-

# app/managers/user_manager.py
import re
import structlog
from uuid import UUID
from fastapi import Request, HTTPException
from fastapi_users import BaseUserManager, UUIDIDMixin
from fastapi_users.password import PasswordHelper, Argon2PasswordHasher
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from app.models.user import User
from app.core.config import settings
from app.core.redis import get_redis_client
from app.metrics.auth import increment_auth_metric

logger = structlog.get_logger("user_manager")

# 企业级Argon2密码哈希器（参数调优）
argon2_hasher = Argon2PasswordHasher(
    memory_cost=settings.ARGON2_MEMORY_COST,
    time_cost=settings.ARGON2_TIME_COST,
    parallelism=settings.ARGON2_PARALLELISM
)
password_helper = PasswordHelper([argon2_hasher])

class UserManager(UUIDIDMixin, BaseUserManager[User, UUID]):
    password_helper = password_helper
    reset_password_token_secret = settings.jwt_private_key
    verification_token_secret = settings.jwt_private_key

    # ========== 高性能优化：用户信息缓存 ==========
    async def get_by_id(self, user_id: UUID) -> User:
        """重写get_by_id，添加Redis缓存"""
        redis = await get_redis_client()
        cache_key = f"user:{user_id}"
        # 先查缓存
        cached_user = await redis.hgetall(cache_key)
        if cached_user:
            # 缓存命中，构建User对象（简化示例，可封装为工具函数）
            user = User(
                id=UUID(cached_user["id"]),
                email=cached_user["email"],
                username=cached_user["username"],
                tenant_id=UUID(cached_user["tenant_id"]),
                role=cached_user["role"],
                is_active=bool(cached_user["is_active"]),
                is_verified=bool(cached_user["is_verified"]),
                is_superuser=bool(cached_user["is_superuser"])
            )
            increment_auth_metric("user_cache_hit")
            return user
        # 缓存未命中，查数据库
        user = await super().get_by_id(user_id)
        # 写入缓存（TTL=5分钟）
        await redis.hmset_dict(
            cache_key,
            id=str(user.id),
            email=user.email,
            username=user.username,
            tenant_id=str(user.tenant_id),
            role=user.role,
            is_active=str(user.is_active),
            is_verified=str(user.is_verified),
            is_superuser=str(user.is_superuser)
        )
        await redis.expire(cache_key, settings.CACHE_TTL_SECONDS)
        increment_auth_metric("user_cache_miss")
        return user

    # ========== 企业级密码策略强化 ==========
    async def validate_password(self, password: str, user: User) -> None:
        """自定义密码验证（企业级复杂度）"""
        # 长度检查
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters")
        # 包含大写字母
        if settings.PASSWORD_REQUIRE_UPPER and not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter")
        # 包含数字
        if settings.PASSWORD_REQUIRE_NUMBER and not re.search(r"\d", password):
            raise ValueError("Password must contain at least one number")
        # 包含特殊字符
        if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValueError("Password must contain at least one special character")
        # 不能包含邮箱/用户名
        if user.email in password or user.username in password:
            raise ValueError("Password must not contain email or username")
        await super().validate_password(password, user)

    # ========== 审计日志（企业级合规） ==========
    async def on_after_register(self, user: User, request: Request | None = None):
        logger.info(
            "user_registered",
            user_id=str(user.id),
            username=user.username,
            tenant_id=str(user.tenant_id),
            ip=request.client.host if request else "unknown"
        )
        increment_auth_metric("user_register")

    async def on_after_login(
        self, user: User, request: Request | None = None, token: str | None = None
    ):
        logger.info(
            "user_logged_in",
            user_id=str(user.id),
            username=user.username,
            tenant_id=str(user.tenant_id),
            ip=request.client.host if request else "unknown",
            token=token[:20] + "..." if token else None
        )
        increment_auth_metric("user_login")

    async def on_after_request_reset_password(self, user: User, token: str, request: Request | None = None):
        logger.warning(
            "password_reset_requested",
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            ip=request.client.host if request else "unknown"
        )
        increment_auth_metric("password_reset_request")

    # ========== 多租户隔离 ==========
    async def create(self, user_create, safe: bool = False, request: Request | None = None) -> User:
        """重写创建用户，强制租户隔离"""
        if settings.MULTI_TENANT_ENABLED and not hasattr(user_create, "tenant_id"):
            # 从请求中提取租户ID（如Header/Tenant域名）
            tenant_id = request.headers.get("X-Tenant-ID", settings.DEFAULT_TENANT_ID)
            user_create.tenant_id = tenant_id
        return await super().create(user_create, safe, request)

# ========== 依赖注入 ==========
async def get_user_db(session=Depends(get_write_db)):
    """用户数据库依赖（写操作走主库）"""
    yield SQLAlchemyUserDatabase(session, User)

async def get_user_manager(user_db=Depends(get_user_db)):
    """用户管理器依赖"""
    yield UserManager(user_db)
