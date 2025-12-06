# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import (
    OAuth2PasswordBearer, 
    HTTPBearer, 
    HTTPAuthorizationCredentials
)
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis
from uuid import uuid4
import structlog

from .sc_config import security_settings
from ..config.database import get_db
from ..domain.models.user import User
from ..domain.repositories.user import UserRepository

logger = structlog.get_logger()
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"], 
    deprecated="auto",
    argon2__time_cost=3,
    argon2__memory_cost=65536,
    argon2__parallelism=4,
    argon2__hash_len=32
)

# OAuth2 schemes
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False
)
http_bearer = HTTPBearer(auto_error=False)

class AdvancedAuthService:
    """高级认证服务"""
    
    def __init__(self):
        self.redis_client = None
    
    async def init_redis(self):
        """初始化Redis连接"""
        self.redis_client = redis.from_url(
            "redis://localhost:6379",
            decode_responses=True,
            ssl=security_settings.REDIS_SECURE_CONNECTION,
            ssl_cert_reqs="required" if security_settings.REDIS_SSL_VERIFY else "none"
        )
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """验证密码"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """生成密码哈希"""
        return pwd_context.hash(password)
    
    def validate_password_policy(self, password: str) -> bool:
        """验证密码策略"""
        if len(password) < security_settings.PASSWORD_MIN_LENGTH:
            return False
        
        checks = {
            'uppercase': security_settings.PASSWORD_REQUIRE_UPPERCASE,
            'lowercase': security_settings.PASSWORD_REQUIRE_LOWERCASE,
            'digits': security_settings.PASSWORD_REQUIRE_DIGITS,
            'special': security_settings.PASSWORD_REQUIRE_SPECIAL,
        }
        
        if checks['uppercase'] and not any(c.isupper() for c in password):
            return False
        if checks['lowercase'] and not any(c.islower() for c in password):
            return False
        if checks['digits'] and not any(c.isdigit() for c in password):
            return False
        if checks['special'] and not any(not c.isalnum() for c in password):
            return False
        
        return True
    
    async def check_password_history(self, user_id: str, new_password: str) -> bool:
        """检查密码是否在历史记录中"""
        if not self.redis_client:
            await self.init_redis()
        
        history_key = f"password_history:{user_id}"
        password_history = await self.redis_client.lrange(history_key, 0, -1)
        
        for old_hash in password_history:
            if pwd_context.verify(new_password, old_hash):
                return False
        
        return True
    
    async def add_password_to_history(self, user_id: str, password_hash: str):
        """添加密码到历史记录"""
        if not self.redis_client:
            await self.init_redis()
        
        history_key = f"password_history:{user_id}"
        await self.redis_client.lpush(history_key, password_hash)
        await self.redis_client.ltrim(history_key, 0, security_settings.PASSWORD_HISTORY_SIZE - 1)
    
    async def check_login_attempts(self, user_id: str) -> bool:
        """检查登录尝试次数"""
        if not self.redis_client:
            await self.init_redis()
        
        attempts_key = f"login_attempts:{user_id}"
        attempts = await self.redis_client.get(attempts_key)
        
        if attempts and int(attempts) >= security_settings.MAX_LOGIN_ATTEMPTS:
            lockout_key = f"account_lockout:{user_id}"
            lockout_time = await self.redis_client.get(lockout_key)
            
            if not lockout_time:
                # 锁定账户
                await self.redis_client.setex(
                    lockout_key,
                    security_settings.ACCOUNT_LOCKOUT_MINUTES * 60,
                    str(datetime.utcnow())
                )
                logger.warning("Account locked due to too many failed attempts", user_id=user_id)
            
            return False
        
        return True
    
    async def increment_login_attempts(self, user_id: str):
        """增加登录尝试次数"""
        if not self.redis_client:
            await self.init_redis()
        
        attempts_key = f"login_attempts:{user_id}"
        await self.redis_client.incr(attempts_key)
        await self.redis_client.expire(attempts_key, 300)  # 5分钟过期
    
    async def reset_login_attempts(self, user_id: str):
        """重置登录尝试次数"""
        if not self.redis_client:
            await self.init_redis()
        
        attempts_key = f"login_attempts:{user_id}"
        lockout_key = f"account_lockout:{user_id}"
        
        await self.redis_client.delete(attempts_key)
        await self.redis_client.delete(lockout_key)
    
    def create_access_token(
        self,
        subject: str,
        user_data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None,
        scopes: List[str] = None
    ) -> str:
        """创建访问令牌"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
            "aud": security_settings.JWT_AUDIENCE,
            "iss": security_settings.JWT_ISSUER,
            "jti": str(uuid4()),
            "scopes": scopes or ["read"],
            "user": {
                "id": user_data.get("id"),
                "email": user_data.get("email"),
                "roles": user_data.get("roles", []),
                "permissions": user_data.get("permissions", [])
            }
        }
        
        encoded_jwt = jwt.encode(
            to_encode,
            security_settings.JWT_SECRET_KEY,
            algorithm=security_settings.JWT_ALGORITHM
        )
        
        # 记录令牌颁发
        logger.info("Access token issued", user_id=subject, jti=to_encode["jti"])
        
        return encoded_jwt
    
    def create_refresh_token(self, subject: str) -> str:
        """创建刷新令牌"""
        expire = datetime.utcnow() + timedelta(
            days=security_settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh",
            "aud": security_settings.JWT_AUDIENCE,
            "iss": security_settings.JWT_ISSUER,
            "jti": str(uuid4()),
        }
        
        encoded_jwt = jwt.encode(
            to_encode,
            security_settings.JWT_SECRET_KEY,
            algorithm=security_settings.JWT_ALGORITHM
        )
        
        return encoded_jwt
    
    async def blacklist_token(self, token: str, expires_in: int = None):
        """将令牌加入黑名单"""
        if not self.redis_client:
            await self.init_redis()
        
        try:
            payload = jwt.decode(
                token,
                security_settings.JWT_SECRET_KEY,
                algorithms=[security_settings.JWT_ALGORITHM],
                audience=security_settings.JWT_AUDIENCE,
                issuer=security_settings.JWT_ISSUER
            )
            
            jti = payload.get("jti")
            exp = payload.get("exp")
            
            if jti:
                # 设置黑名单，直到令牌过期
                ttl = expires_in or (exp - datetime.utcnow().timestamp())
                if ttl > 0:
                    await self.redis_client.setex(
                        f"token_blacklist:{jti}",
                        int(ttl),
                        "1"
                    )
        
        except JWTError:
            pass
    
    async def is_token_blacklisted(self, jti: str) -> bool:
        """检查令牌是否在黑名单中"""
        if not self.redis_client:
            await self.init_redis()
        
        blacklisted = await self.redis_client.exists(f"token_blacklist:{jti}")
        return bool(blacklisted)
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """解码并验证JWT令牌"""
        try:
            payload = jwt.decode(
                token,
                security_settings.JWT_SECRET_KEY,
                algorithms=[security_settings.JWT_ALGORITHM],
                audience=security_settings.JWT_AUDIENCE,
                issuer=security_settings.JWT_ISSUER
            )
            
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
        token: Optional[str] = Depends(oauth2_scheme),
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        """获取当前认证用户"""
        # 支持两种认证方式：Bearer token 和 API Key
        auth_token = token
        if not auth_token and credentials:
            if credentials.scheme.lower() == "bearer":
                auth_token = credentials.credentials
        
        if not auth_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        try:
            payload = self.decode_token(auth_token)
            
            # 检查令牌类型
            token_type = payload.get("type")
            if token_type != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                )
            
            # 检查令牌是否在黑名单中
            jti = payload.get("jti")
            if jti and await self.is_token_blacklisted(jti):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token revoked",
                )
            
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
            
            # 检查用户权限是否已更改
            user_permissions = set(user.permissions or [])
            token_permissions = set(payload.get("user", {}).get("permissions", []))
            
            if user_permissions != token_permissions:
                # 权限已更改，需要重新登录
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Permissions changed, please re-authenticate",
                )
            
            # 记录成功的认证
            logger.info("User authenticated successfully", user_id=user_id)
            
            return user
        
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )

# 创建全局认证服务实例
auth_service = AdvancedAuthService()