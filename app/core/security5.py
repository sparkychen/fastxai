# -*- coding: utf-8 -*-

# app/core/security.py
import structlog
from fastapi import Request, HTTPException
from fastapi_users.authentication import AuthenticationBackend, BearerTransport, JWTStrategy
from app.core.co_config import settings
from app.core.redis import get_redis_client
from app.metrics.auth import increment_auth_metric

logger = structlog.get_logger("security")

# ========== 企业级JWT策略（非对称加密+黑名单） ==========
class EnterpriseJWTStrategy(JWTStrategy):
    async def read_token(self, token: str, request: Request | None = None) -> dict | None:
        """重写Token读取，添加黑名单检查"""
        # 1. 检查Token是否在黑名单中
        redis = await get_redis_client()
        if await redis.get(f"jwt_blacklist:{token}"):
            increment_auth_metric("jwt_blacklist_hit")
            raise HTTPException(status_code=401, detail="Token has been revoked")
        # 2. 非对称加密验证Token
        try:
            payload = await super().read_token(token, request)
            increment_auth_metric("jwt_verify_success")
            return payload
        except Exception as e:
            increment_auth_metric("jwt_verify_failure")
            logger.error("JWT verification failed", error=str(e))
            raise HTTPException(status_code=401, detail="Invalid token") from e

    async def write_token(self, user) -> str:
        """重写Token生成，添加租户信息"""
        # 向JWT载荷中添加租户ID（多租户适配）
        payload = {
            "sub": str(user.id),
            "tenant_id": str(user.tenant_id),
            "role": user.role
        }
        return await super().write_token(user, payload=payload)

# ========== 认证后端配置 ==========
bearer_transport = BearerTransport(tokenUrl=f"{settings.API_PREFIX}/auth/jwt/login")

def get_jwt_strategy() -> JWTStrategy:
    return EnterpriseJWTStrategy(
        secret=settings.jwt_private_key,
        public_key=settings.jwt_public_key,
        lifetime_seconds=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        algorithm=settings.JWT_ALGORITHM
    )

auth_backend = AuthenticationBackend(
    name="jwt-enterprise",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy
)

# ========== 令牌吊销（加入黑名单） ==========
async def revoke_token(token: str):
    """吊销Token（加入Redis黑名单）"""
    redis = await get_redis_client()
    await redis.setex(
        f"jwt_blacklist:{token}",
        settings.JWT_BLACKLIST_TTL_SECONDS,
        "revoked"
    )
    increment_auth_metric("jwt_revoked")
    logger.info("Token revoked", token=token[:20] + "...")
