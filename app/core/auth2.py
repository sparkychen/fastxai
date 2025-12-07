# -*- coding: utf-8 -*-

from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any, List
from uuid import UUID
import jwt
import pyotp
import bcrypt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_users import FastAPIUsers, UUIDIDMixin
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users.exceptions import UserNotExists
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext
from app.database.postgres import get_db
from app.database.models.user import User, UserRole
from app.core.config import settings
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()
# ================= 1. 密码哈希配置 =================
pwd_context = CryptContext(
    schemes=[settings.PASSWORD_HASH_ALGORITHM],
    bcrypt__rounds=settings.PASSWORD_BCRYPT_ROUNDS,
    deprecated="auto"
)

# ================= 2. JWT策略（增强安全） =================
def get_jwt_strategy() -> JWTStrategy:
    """自定义JWT策略（添加额外安全字段）"""
    return JWTStrategy(
        secret=settings.SECRET_KEY,
        lifetime_seconds=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        algorithm=settings.JWT_ALGORITHM,
        # 自定义JWT编码
        encode_payload=lambda payload, secret, algorithm: jwt.encode(
            {
                **payload,
                "iat": datetime.now(UTC),  # 签发时间
                "nbf": datetime.now(UTC),  # 生效时间
                "jti": str(UUID(int=jwt.utils.base64url_decode(payload["sub"]))),  # 唯一ID
            },
            secret,
            algorithm=algorithm,
            headers={"kid": "enterprise-fastapi-v1"}  # 密钥ID
        ),
    )

# ================= 3. 认证后端 =================
bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")
auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)

# ================= 4. MFA/双因素认证 =================
class MFAService:
    """MFA服务（TOTP协议，兼容Google Authenticator）"""
    @staticmethod
    def generate_secret(user: User) -> str:
        """生成MFA密钥"""
        secret = pyotp.random_base32()
        user.mfa_secret = secret  # 需在User模型添加mfa_secret字段
        return secret

    @staticmethod
    def get_provisioning_uri(user: User, secret: str) -> str:
        """生成MFA配置URI（用于扫码）"""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name=settings.MFA_ISSUER_NAME
        )

    @staticmethod
    async def verify_mfa_code(user: User, code: str) -> bool:
        """验证MFA验证码"""
        if not user.mfa_secret:
            return False
        totp = pyotp.totp.TOTP(user.mfa_secret)
        # 允许30秒时间窗口（容错）
        return totp.verify(code, valid_window=1)

mfa_service = MFAService()

# ================= 5. 令牌黑名单（分布式） =================
class TokenBlacklist:
    """基于Redis的令牌黑名单（高可用）"""
    def __init__(self):
        import aioredis
        self.redis = aioredis.from_url(security_settings.RATE_LIMIT_STORAGE_URL)

    async def add_token(self, token: str, expires_at: datetime):
        """添加令牌到黑名单"""
        ttl = int((expires_at - datetime.now(UTC)).total_seconds())
        if ttl > 0:
            await self.redis.setex(f"blacklist:{token}", ttl, "1")
            logger.info("Token added to blacklist", jti=token[:10] + "...")

    async def is_blacklisted(self, token: str) -> bool:
        """检查令牌是否在黑名单"""
        return await self.redis.exists(f"blacklist:{token}") == 1

token_blacklist = TokenBlacklist()

# ================= 6. 权限验证 =================
class PermissionChecker:
    """RBAC细粒度权限检查"""
    @staticmethod
    def has_role(user: User, roles: List[UserRole]) -> bool:
        """检查用户角色"""
        if user.is_superuser:
            return True
        return user.role in roles

    @staticmethod
    def has_permission(user: User, permission: str) -> bool:
        """检查用户细粒度权限"""
        if user.is_superuser:
            return True
        return permission in (user.permissions or [])

    @staticmethod
    def has_data_permission(user: User, resource_id: UUID) -> bool:
        """数据级权限检查（示例：仅资源所属者/管理员可访问）"""
        # 需根据业务实现，例如：
        # - 检查user.id是否为资源创建者
        # - 检查用户所属租户是否有权限
        return True

permission_checker = PermissionChecker()

# ================= 7. 依赖注入：权限验证 =================
def require_roles(roles: List[UserRole]):
    """依赖：要求指定角色"""
    async def _require_roles(user: User = Depends(get_current_active_user)):
        if not permission_checker.has_role(user, roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions"
            )
        return user
    return _require_roles

def require_permission(permission: str):
    """依赖：要求指定权限"""
    async def _require_permission(user: User = Depends(get_current_active_user)):
        if not permission_checker.has_permission(user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient granular permissions"
            )
        return user
    return _require_permission

# ================= 8. FastAPI-Users集成 =================
async def get_user_db(session: AsyncSession = Depends(get_db)):
    yield SQLAlchemyUserDatabase(session, User)

# 自定义用户管理器（增强安全）
class CustomUserManager(UUIDIDMixin, BaseUserManager[User, UUID]):
    reset_password_token_secret = settings.SECRET_KEY
    verification_token_secret = settings.SECRET_KEY

    async def validate_password(
        self, password: str, user: User
    ) -> None:
        """企业级密码验证"""
        # 长度检查
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            raise InvalidPasswordException(
                detail=f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
            )
        # 复杂度检查
        if settings.PASSWORD_REQUIRE_UPPER and not any(c.isupper() for c in password):
            raise InvalidPasswordException(detail="Password must contain uppercase letters")
        if settings.PASSWORD_REQUIRE_LOWER and not any(c.islower() for c in password):
            raise InvalidPasswordException(detail="Password must contain lowercase letters")
        if settings.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
            raise InvalidPasswordException(detail="Password must contain numbers")
        if settings.PASSWORD_REQUIRE_SYMBOLS and not any(not c.isalnum() for c in password):
            raise InvalidPasswordException(detail="Password must contain symbols")
        # 检查常见弱密码（可扩展）
        common_passwords = ["123456", "password", "admin123", user.email, user.username]
        if password.lower() in [p.lower() for p in common_passwords if p]:
            raise InvalidPasswordException(detail="Password is too common")

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        """注册后钩子：强制MFA配置"""
        logger.info("User registered", user_id=user.id, email=user.email)
        if settings.MFA_REQUIRED and not user.mfa_secret:
            # 生成MFA密钥
            secret = mfa_service.generate_secret(user)
            await self.user_db.update(user)
            logger.info("MFA secret generated for user", user_id=user.id)

    async def on_after_login(
        self, user: User, request: Optional[Request] = None, response: Optional[Response] = None
    ):
        """登录后钩子：记录登录日志"""
        user.last_login_at = datetime.now(UTC)
        await self.user_db.update(user)
        logger.info("User logged in", user_id=user.id, ip=request.client.host if request else None)

    async def on_after_logout(self, user: User, token: str, request: Optional[Request] = None):
        """登出后钩子：加入黑名单"""
        # 解析令牌过期时间
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
            )
            expires_at = datetime.fromtimestamp(payload["exp"], UTC)
            await token_blacklist.add_token(token, expires_at)
        except Exception as e:
            logger.error("Failed to blacklist token", error=str(e))
        logger.info("User logged out", user_id=user.id)

async def get_user_manager(user_db=Depends(get_user_db)):
    yield CustomUserManager(user_db)

fastapi_users = FastAPIUsers[User, UUID](get_user_manager, [auth_backend])

# 依赖：获取当前用户
get_current_user = fastapi_users.current_user(optional=True)
get_current_active_user = fastapi_users.current_user(active=True)
get_current_superuser = fastapi_users.current_user(active=True, superuser=True)
