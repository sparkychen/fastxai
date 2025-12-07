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
from app.models.database import User, MFABackupCode
from passlib.context import CryptContext
from app.core.config import settings
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

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
    def __init__(self, redis: Redis):
        self.redis = redis
    
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