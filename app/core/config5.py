# -*- coding: utf-8 -*-

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import EmailStr, SecretStr, Field
from typing import List, Optional, Literal
from pathlib import Path
from datetime import timedelta

# # 核心依赖（异步+安全+缓存）
# pip install fastapi-users[sqlalchemy,asyncpg,jwt,argon2]
# # 缓存/速率限制/监控
# pip install aioredis slowapi limits structlog prometheus-fastapi-instrumentator
# # 安全工具
# pip install fastapi-security-utils email-validator aiosmtplib
# # 配置管理
# pip install pydantic-settings python-dotenv

class Settings(BaseSettings):
    # 应用配置
    APP_NAME: str = "FastAPI-Users Enterprise"
    ENV: Literal["dev", "test", "prod"] = "prod"
    API_PREFIX: str = "/api/v1"
    
    # 数据库配置（生产级读写分离）
    DB_WRITE_DSN: str = "postgresql+asyncpg://user:pass@master-db:5432/app"
    DB_READ_DSNS: List[str] = ["postgresql+asyncpg://user:pass@slave1-db:5432/app"]
    DB_POOL_SIZE: int = 20          # 常驻连接数（CPU核心*2）
    DB_MAX_OVERFLOW: int = 40       # 应急溢出连接
    DB_POOL_RECYCLE: int = 280      # 连接回收（<数据库 wait_timeout）
    DB_POOL_PRE_PING: bool = True   # 连接健康检查
    DB_ENABLE_RW_SEPARATION: bool = True
    
    # Redis 配置（缓存/黑名单/速率限制）
    REDIS_URL: str = "redis://redis:6379/0"
    REDIS_PASSWORD: Optional[SecretStr] = None
    REDIS_DB: int = 0
    CACHE_TTL_SECONDS: int = 300    # 用户信息缓存超时（5分钟）
    
    # JWT 配置（企业级非对称加密）
    JWT_PRIVATE_KEY_PATH: Path = Path("keys/private.pem")
    JWT_PUBLIC_KEY_PATH: Path = Path("keys/public.pem")
    JWT_ALGORITHM: str = "RS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_BLACKLIST_TTL_SECONDS: int = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60  # 黑名单超时
    
    # 密码策略（企业级强化）
    PASSWORD_MIN_LENGTH: int = 10
    PASSWORD_REQUIRE_UPPER: bool = True
    PASSWORD_REQUIRE_NUMBER: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    ARGON2_MEMORY_COST: int = 102400  # Argon2 内存成本（越高越安全）
    ARGON2_TIME_COST: int = 3         # 时间成本
    ARGON2_PARALLELISM: int = 4       # 并行度
    
    # 速率限制（防暴力破解）
    RATE_LIMIT_LOGIN: str = "5/minute"  # 登录接口限制
    RATE_LIMIT_REGISTER: str = "10/hour" # 注册接口限制
    RATE_LIMIT_RESET_PASSWORD: str = "3/hour" # 密码重置限制
    
    # 邮箱配置（生产级SMTP）
    SMTP_HOST: str = "smtp.enterprise.com"
    SMTP_PORT: int = 587
    SMTP_USER: EmailStr = "noreply@enterprise.com"
    SMTP_PASSWORD: SecretStr = SecretStr("smtp-secret")
    SMTP_TLS: bool = True
    EMAIL_FROM: EmailStr = "noreply@enterprise.com"
    EMAIL_VERIFY_URL: str = "https://app.enterprise.com/verify-email"
    PASSWORD_RESET_URL: str = "https://app.enterprise.com/reset-password"
    
    # CORS/CSRF
    CORS_ORIGINS: List[str] = ["https://app.enterprise.com"]
    CSRF_SECRET: SecretStr = SecretStr("csrf-secret-32bytes")
    CSRF_COOKIE_SECURE: bool = True  # 生产环境开启HTTPS
    CSRF_COOKIE_HTTPONLY: bool = True
    
    # 多租户配置
    MULTI_TENANT_ENABLED: bool = True
    DEFAULT_TENANT_ID: str = "default-tenant"

    # 生产级配置加载（优先级：环境变量 > .env.prod）
    model_config = SettingsConfigDict(
        env_file=f".env.{ENV}",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @property
    def jwt_private_key(self) -> str:
        """加载RSA私钥（生产级：从密钥管理系统读取）"""
        return self.JWT_PRIVATE_KEY_PATH.read_text() if self.JWT_PRIVATE_KEY_PATH.exists() else ""

    @property
    def jwt_public_key(self) -> str:
        """加载RSA公钥"""
        return self.JWT_PUBLIC_KEY_PATH.read_text() if self.JWT_PUBLIC_KEY_PATH.exists() else ""

settings = Settings()
