# -*- coding: utf-8 -*-

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, EmailStr
from typing import List, Literal, Optional
from pathlib import Path
import os

class SecuritySettings(BaseSettings):
    # ================= 基础安全配置 =================
    ENVIRONMENT: Literal["development", "staging", "production"] = "production"
    DEBUG: bool = False
    SECRET_KEY: str = os.getenv("SECRET_KEY")  # 生产环境从密钥管理服务获取
    ROOT_DIR: Path = Path(__file__).parent.parent.parent
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    # CORS安全配置（严格限制）
    CORS_ORIGINS: List[str] = []  # 生产环境显式指定，禁止通配符
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    CORS_ALLOW_HEADERS: List[str] = ["Authorization", "Content-Type", "X-Request-ID"]
    
    # ================= 认证配置 =================
    # JWT配置（高安全）
    JWT_ALGORITHM: str = "HS512"  # 强算法
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # 短期访问令牌（降低泄露风险）
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_REFRESH_TOKEN_ROTATION: bool = True  # 刷新令牌轮换（防止重放）
    JWT_BLACKLIST_ENABLED: bool = True  # 令牌黑名单
    JWT_BLACKLIST_TOKEN_TYPE: Literal["access", "refresh", "both"] = "both"
    # MFA配置
    MFA_REQUIRED: bool = True  # 生产环境强制MFA
    MFA_ISSUER_NAME: str = "Enterprise FastAPI"
    # 密码策略（企业级）
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_REQUIRE_UPPER: bool = True
    PASSWORD_REQUIRE_LOWER: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_SYMBOLS: bool = True
    PASSWORD_HASH_ALGORITHM: str = "bcrypt"  # 慢哈希算法
    PASSWORD_BCRYPT_ROUNDS: int = 14  # 计算强度（越高越安全，性能需平衡）
    
    # ================= 速率限制配置 =================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_STORAGE_URL: str = "redis://redis:6379/0"  # 分布式限流存储
    RATE_LIMIT_DEFAULT: str = "100/minute"  # 默认限流
    RATE_LIMIT_AUTH: str = "300/minute"  # 认证接口限流
    RATE_LIMIT_ADMIN: str = "500/minute"  # 管理员接口限流
    
    # ================= 数据安全配置 =================
    ENCRYPTION_ALGORITHM: str = "AES-256-GCM"  # 对称加密算法
    ENCRYPTION_KEY: bytes = os.getenv("ENCRYPTION_KEY", "").encode()  # 32字节密钥
    SENSITIVE_FIELDS: List[str] = ["password", "phone", "email", "id_card", "bank_card"]
    DATA_MASKING_CHAR: str = "*"  # 脱敏字符
    
    # ================= 安全头部配置 =================
    SECURITY_HEADERS_ENABLED: bool = True
    CONTENT_SECURITY_POLICY: str = (
        "default-src 'self'; "
        "script-src 'self' 'strict-dynamic'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none';"
    )
    
    # ================= 审计日志配置 =================
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_LEVEL: Literal["INFO", "WARNING", "ERROR"] = "INFO"
    AUDIT_LOG_FILE: Path = ROOT_DIR / "logs/audit.log"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # 配置验证
    @field_validator("SECRET_KEY")
    def validate_secret_key(cls, v):
        if not v and cls.ENVIRONMENT == "production":
            raise ValueError("SECRET_KEY must be set in production environment")
        return v

    @field_validator("ENCRYPTION_KEY")
    def validate_encryption_key(cls, v):
        if len(v) != 32 and cls.ENVIRONMENT == "production":
            raise ValueError("ENCRYPTION_KEY must be 32 bytes (256 bits) in production")
        return v

    @field_validator("ALLOWED_HOSTS", "CORS_ORIGINS", mode="before")
    def parse_list(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",")]
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

# 全局安全配置实例
security_settings = SecuritySettings()
