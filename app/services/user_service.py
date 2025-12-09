# -*- coding: utf-8 -*-

# app/managers/user_manager.py
import re
import structlog
from fastapi import Request, HTTPException, Depends, status
from fastapi_users.password import PasswordHelper
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from app.models.user import User
from app.core.config import settings
from app.database.redis import get_redis_client
# from app.core.auth import increment_auth_metric
from app.database.postgres import get_auto_rw_db, auto_rw_separation
from fastapi_users import BaseUserManager, IntegerIDMixin, schemas, exceptions, models
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.user import User
from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)
from passlib.context import CryptContext
# from fastapi_users.db.sqlalchemy import SQLAlchemyAccessTokenDatabase  # 修正导入
# from fastapi_users.db.sqlalchemy import AccessToken  # 修正：AccessToken模型从这里导入
from app.core.config import settings

logger = structlog.get_logger("user_manager")

# 企业级Argon2密码哈希器（参数调优）
argon2_hasher = CryptContext(schemes=["argon2"])
password_helper = PasswordHelper([argon2_hasher])

class UserManager(IntegerIDMixin, BaseUserManager[User, int]):
    password_helper = password_helper
    reset_password_token_secret = settings.jwt_private_key
    verification_token_secret = settings.jwt_private_key

    async def create(
        self,
        user_create: schemas.UC,
        safe: bool = False,
        request: Request | None = None,
    ) -> User:
        """
        扩展注册逻辑：
        1. 检查用户名唯一性
        2. 检查手机号唯一性
        3. 记录审计日志
        4. 强制初始状态为 INACTIVE（需验证激活）
        """
        # 1. 检查用户名是否已存在
        existing_user = await self.user_db.get_by_username(user_create.username)
        if existing_user:
            raise exceptions.UserAlreadyExists()

        # 2. 检查手机号是否已存在（若填写）
        if user_create.phone:
            existing_phone = await self.user_db.get_by_phone(user_create.phone)
            if existing_phone:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="手机号已被注册",
                )

        # 3. 覆盖状态为 INACTIVE（需验证激活）
        user_create_dict = user_create.dict()
        user_create_dict["status"] = "inactive"
        user_create = schemas.UserCreate(**user_create_dict)
        # 4. 调用父类创建逻辑
        user = await super().create(user_create, safe, request)

        # 5. 记录审计日志（企业级：注册日志）
        logger.info(
            "user_registered",
            user_id=user.id,
            username=user.username,
            email=user.email,
            ip=request.client.host if request else "unknown",
        )

        return user

    # ========== 高性能优化：用户信息缓存 ==========
    async def get_by_id(self, user_id: int) -> User:
        """重写get_by_id，添加Redis缓存"""
        redis = await get_redis_client()
        cache_key = f"user:{user_id}"
        # 先查缓存
        cached_user = await redis.hgetall(cache_key)
        if cached_user:
            # 缓存命中，构建User对象（简化示例，可封装为工具函数）
            user = User(
                id=cached_user["id"],
                email=cached_user["email"],
                username=cached_user["username"],
                tenant_id=cached_user["tenant_id"],
                role=cached_user["role"],
                is_active=bool(cached_user["is_active"]),
                is_verified=bool(cached_user["is_verified"]),
                is_superuser=bool(cached_user["is_superuser"])
            )
            # increment_auth_metric("user_cache_hit")
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
        """登录时检查用户状态（锁定/禁用则拒绝）"""
        if user.status != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"用户状态异常：{user.status}",
            )
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
# async def get_user_db(session=Depends(get_write_db)):
#     """用户数据库依赖（写操作走主库）"""
#     yield SQLAlchemyUserDatabase(session, User)

class CustomSQLAlchemyUserDatabase(SQLAlchemyUserDatabase):
    """扩展数据库适配器，支持自定义字段（username/phone）查询"""
    async def get_by_username(self, username: str) -> User | None:
        """根据用户名查询用户"""
        statement = select(self.user_table).where(self.user_table.username == username)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_by_phone(self, phone: str) -> User | None:
        """根据手机号查询用户"""
        statement = select(self.user_table).where(self.user_table.phone == phone)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

@auto_rw_separation
async def get_user_db(session: AsyncSession = Depends(get_auto_rw_db)):
    """FastAPI-Users 数据库适配器"""
    yield CustomSQLAlchemyUserDatabase(session, User)

async def get_user_manager(user_db=Depends(get_user_db)):
    """用户管理器依赖"""
    yield UserManager(user_db)


# 刷新令牌数据库适配器（修正导入后）
async def get_access_token_db(session: AsyncSession = Depends(get_auto_rw_db)):
    yield SQLAlchemyAccessTokenDatabase(session, AccessToken)

# 其余JWT策略、Cookie传输、认证后端逻辑保持不变
def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(
        secret=settings.SECRET_KEY,
        lifetime_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # 访问令牌有效期
        refresh_lifetime_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,  # 刷新令牌有效期
    )
# ========== Cookie 传输（15.x 版本兼容） ==========
cookie_transport = CookieTransport(
    cookie_name="fastapi_users_token",
    cookie_max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    cookie_secure=settings.ENV == "prod",  # 生产环境仅HTTPS
    cookie_httponly=True,                  # 防XSS
    cookie_samesite="lax",                 # 防CSRF
)
# ========== 认证后端（无状态 JWT + Cookie） ==========
auth_backend = AuthenticationBackend(
    name="jwt-cookie",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)






