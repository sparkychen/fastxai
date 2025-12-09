# -*- coding: utf-8 -*-

import pyotp
import qrcode
import base64
from io import BytesIO
from typing import List, Optional, Tuple
import secrets
import hashlib
from datetime import datetime, timedelta
from redis.asyncio import Redis, RedisCluster
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.user import User, MFABackupCode, UserRole
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import HTTPException, status
from app.core.config import settings
from app.core.logger import logger

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(data: dict) -> str:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode = data.copy()
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            return payload
        except JWTError:
            return None
    
    @classmethod
    def authenticate_user(cls, db: Session, email: str, password: str) -> Optional[User]:
        user = db.query(User).filter(User.email == email).first()
        if not user or not cls.verify_password(password, user.hashed_password):
            return None
        return user

class MFAService:
    def __init__(self, redis: Redis = None):
        if Redis:
            self.redis = redis
        else:
            self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
        self._key = self._generate_key()
        self._fernet = Fernet(self._key)
        self._cache = None  # 由依赖注入设置

    def _generate_key(self) -> bytes:
        """生成加密密钥（使用 MFA_SECRET_KEY）"""
        salt = b"mfa_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(settings.MFA_SECRET_KEY.encode()))

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
    
    def generate_totp_secret(self) -> str:
        """生成 TOTP 密钥"""
        return pyotp.random_base32()
    
    def generate_backup_codes(self, count: int = settings.MFA_BACKUP_CODES) -> List[str]:
        """生成备份代码"""
        return [secrets.token_hex(4).upper() for _ in range(count)]
    
    def get_totp_uri(self, secret: str, email: str) -> str:
        """生成 TOTP URI 用于二维码"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=settings.MFA_ISSUER
        )
    
    def generate_qr_code(self, uri: str) -> str:
        """生成 Base64 编码的二维码"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """验证 TOTP 令牌"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=settings.MFA_VALID_WINDOW)
    
    async def store_mfa_attempt(self, user_id: int, success: bool) -> bool:
        """存储 MFA 尝试并实施速率限制"""
        key = f"mfa_attempts:{user_id}"
        now = datetime.utcnow()
        
        # 获取当前尝试
        attempts = await self.redis.lrange(key, 0, -1)
        attempts = [datetime.fromisoformat(ts.decode()) for ts in attempts]
        
        # 清理过期尝试（1分钟内）
        window_start = now - timedelta(minutes=1)
        valid_attempts = [ts for ts in attempts if ts > window_start]
        
        if success:
            # 成功验证，清空尝试记录
            await self.redis.delete(key)
            return True
        
        # 检查速率限制
        if len(valid_attempts) >= settings.MFA_RATE_LIMIT:
            return False
        
        # 记录新尝试
        await self.redis.lpush(key, now.isoformat())
        await self.redis.ltrim(key, 0, settings.MFA_RATE_LIMIT - 1)
        await self.redis.expire(key, 60)  # 1分钟过期
        
        return True
    
    async def verify_backup_code(self, db: Session, user_id: int, code: str) -> bool:
        """验证备份代码"""
        # 哈希代码进行验证
        hashed_code = hashlib.sha256(code.encode()).hexdigest()
        
        backup_code = db.query(MFABackupCode).filter(
            MFABackupCode.user_id == user_id,
            MFABackupCode.code_hash == hashed_code,
            MFABackupCode.used == False
        ).first()        
        if backup_code:
            backup_code.used = True
            backup_code.used_at = datetime.utcnow()
            db.commit()
            return True        
        return False
    
    def generate_secret(self) -> str:
        """生成安全的 MFA 密钥"""
        return pyotp.random_base32()

    def encrypt_secret(self, secret: str) -> str:
        """加密 MFA 密钥"""
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted_secret: str) -> str:
        """解密 MFA 密钥"""
        return self._fernet.decrypt(encrypted_secret.encode()).decode()

    def generate_qr_code(self, user_email: str, secret: str) -> bytes:
        """生成 MFA 二维码（企业级安全）"""
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=user_email,
            issuer_name="YourApp",
            encoding="base32"
        )
      
        # 生成高质量二维码
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)        

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def generate_backup_codes(self) -> List[str]:
        """生成一次性备份码（企业级）"""
        return [pyotp.random_base32(8) for _ in range(settings.MFA_BACKUP_CODES_COUNT)]


    async def verify_code(self, user: User, code: str) -> bool:
        """验证 MFA 代码（高性能异步）"""
        if not user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled for this account"
            )       

        try:
            # 从缓存获取或解密密钥
            encrypted_secret = user.mfa_secret
            secret = self.decrypt_secret(encrypted_secret)            

            # 验证代码（使用时间窗口）
            return pyotp.TOTP(secret).verify(
                code,
                valid_window=settings.MFA_TOTP_WINDOW
            )

        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )

    async def setup_mfa(self, user: User, db: Session) -> Tuple[bytes, List[str]]:
        """设置 MFA（企业级安全）"""
        secret = self.generate_secret()
        encrypted_secret = self.encrypt_secret(secret)
        # 生成备份码
        backup_codes = self.generate_backup_codes()
        # 保存到数据库（加密存储）
        user.mfa_secret = encrypted_secret
        user.mfa_enabled = True
        user.mfa_backup_codes = self.encrypt_secret("|".join(backup_codes))
        db.commit()      

        # 生成二维码
        qr_code = self.generate_qr_code(user.email, secret)
        return qr_code, backup_codes

class MFAEnrollmentManager:
    """MFA 注册管理器"""
    
    def __init__(self, mfa_service: MFAService):
        self.mfa_service = mfa_service
    
    async def start_enrollment(self, user: User) -> dict:
        """开始 MFA 注册流程"""
        secret = self.mfa_service.generate_totp_secret()
        backup_codes = self.mfa_service.generate_backup_codes()
        
        # 存储临时注册数据（在实际实现中应加密存储）
        enrollment_data = {
            'secret': secret,
            'backup_codes': backup_codes,
            'created_at': datetime.utcnow().isoformat()
        }
        
        # 生成 QR code
        uri = self.mfa_service.get_totp_uri(secret, user.email)
        qr_code = self.mfa_service.generate_qr_code(uri)
        
        return {
            'qr_code': qr_code,
            'secret': secret,  # 仅用于测试，生产环境不应返回
            'backup_codes': backup_codes,
            'manual_entry_key': secret  # 用于手动输入
        }

mfa_service = MFAService()   


# ================= 5. 令牌黑名单（分布式） =================
class TokenBlacklist:
    """基于Redis的令牌黑名单（高可用）"""
    def __init__(self):
        self.redis = Redis.from_url(settings.RATE_LIMIT_STORAGE_URL)

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
    def has_data_permission(user: User, resource_id: str) -> bool:
        """数据级权限检查（示例：仅资源所属者/管理员可访问）"""
        # 需根据业务实现，例如：
        # - 检查user.id是否为资源创建者
        # - 检查用户所属租户是否有权限
        return True

permission_checker = PermissionChecker()