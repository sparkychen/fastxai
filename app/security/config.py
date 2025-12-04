# -*- coding: utf-8 -*-

import os
from typing import Dict, List, Optional, Set
from pydantic import BaseSettings, Field, validator, field_validator
from cryptography.fernet import Fernet
from datetime import timedelta
import redis.asyncio as redis

class SecuritySettings(BaseSettings):
    """安全相关配置"""
    
    # JWT配置
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET_KEY")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_AUDIENCE: str = "fastapi:auth"
    JWT_ISSUER: str = "secure-api"
    
    # 密码策略
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_HISTORY_SIZE: int = 5
    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 30
    
    # API安全
    API_RATE_LIMIT: str = "100/minute"
    CORS_ORIGINS: List[str] = []
    TRUSTED_HOSTS: List[str] = []
    SECURE_COOKIES: bool = True
    SESSION_TIMEOUT_MINUTES: int = 60
    
    # 加密配置
    ENCRYPTION_KEY: str = Field(..., env="ENCRYPTION_KEY")
    DATA_ENCRYPTION_ALGORITHM: str = "AES-GCM"
    
    # Redis安全配置
    REDIS_SECURE_CONNECTION: bool = True
    REDIS_SSL_VERIFY: bool = True
    
    # 安全头配置
    SECURITY_HEADERS: Dict[str, str] = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    
    # IP白名单/黑名单
    IP_WHITELIST: Set[str] = set()
    IP_BLACKLIST: Set[str] = set()
    
    # API密钥管理
    API_KEY_HEADER: str = "X-API-Key"
    API_KEY_EXPIRE_DAYS: int = 90
    
    # 监控配置
    SECURITY_EVENT_LOG_LEVEL: str = "INFO"
    ENABLE_SECURITY_AUDIT: bool = True
    
    @field_validator("JWT_SECRET_KEY", "ENCRYPTION_KEY")
    def validate_key_length(cls, v):
        if len(v) < 32:
            raise ValueError("密钥长度必须至少32个字符")
        return v
    
    @field_validator("CORS_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

class KeyManagementService:
    """密钥管理服务"""
    
    def __init__(self):
        self.fernet = Fernet(SecuritySettings().ENCRYPTION_KEY.encode())
    
    def encrypt_data(self, data: str) -> bytes:
        """加密敏感数据"""
        return self.fernet.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """解密数据"""
        return self.fernet.decrypt(encrypted_data).decode()
    
    def rotate_keys(self):
        """轮换加密密钥"""
        # 实现密钥轮换逻辑
        pass

# 全局安全配置实例
security_settings = SecuritySettings()
key_manager = KeyManagementService()