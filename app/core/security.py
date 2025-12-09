# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from src.domain.repositories.user import UserRepository
from fastapi_users.authentication import AuthenticationBackend, BearerTransport, JWTStrategy
from app.database.redis import get_redis_client
from app.services.auth_service import increment_auth_metric
from app.core.logger import logger

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")



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

class SecurityService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Generate password hash"""
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(data: dict) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def decode_token(token: str) -> dict:
        """Decode and verify JWT token"""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return payload
        except JWTError as e:
            logger.error("Token decode error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    async def get_current_user(
        self, 
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        """Get current authenticated user"""
        try:
            payload = self.decode_token(token)
            user_id: str = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                )
            
            user_repo = UserRepository(db)
            user = await user_repo.get_by_id(user_id)
            if user is None or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive",
                )
            
            return user
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )

security_service = SecurityService()