# -*- coding: utf-8 -*-
# doubao

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, EmailStr
from typing import List, Literal, Optional, Dict
from pathlib import Path
import os
from datetime import timedelta

class AuditLogSettings(BaseSettings):
    """企业级审计日志核心配置"""
    # 基础配置
    ENVIRONMENT: Literal["development", "staging", "production"] = "production"
    DEBUG: bool = False
    APP_NAME: str = "enterprise-fastapi-audit"
    ROOT_DIR: Path = Path(__file__).parent.parent.parent
    
    # 日志级别与格式
    AUDIT_LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    AUDIT_LOG_FORMAT: Literal["json", "console"] = "json"
    AUDIT_LOG_RETENTION_DAYS: int = 90  # 审计日志保留天数（合规要求）
    
    # 高性能配置
    AUDIT_LOG_ASYNC: bool = True  # 异步写入（强制开启）
    AUDIT_LOG_BATCH_ENABLE: bool = True  # 批量写入
    AUDIT_LOG_BATCH_SIZE: int = 100  # 批量阈值
    AUDIT_LOG_BATCH_INTERVAL: float = 5.0  # 批量写入间隔（秒）
    AUDIT_LOG_CACHE_MAX_SIZE: int = 10000  # 内存缓存最大条数（防止OOM）
    
    # 存储配置（分级存储）
    AUDIT_LOG_STORAGE_BACKENDS: List[Literal["file", "redis", "postgres", "es"]] = ["redis", "postgres"]
    # Redis 配置（热数据）
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    REDIS_AUDIT_KEY: str = "enterprise:audit:logs"
    # PostgreSQL 配置（持久化）
    POSTGRES_AUDIT_TABLE: str = "audit_logs"
    # ES 配置（可选，检索）
    ES_URL: str = os.getenv("ES_URL", "http://elasticsearch:9200")
    ES_AUDIT_INDEX: str = "enterprise-audit-logs"
    
    # 安全配置
    AUDIT_LOG_SIGN_ENABLE: bool = True  # 日志签名（防篡改）
    AUDIT_LOG_SIGN_SECRET: bytes = os.getenv("AUDIT_LOG_SIGN_SECRET", "").encode()  # 32字节密钥
    AUDIT_LOG_SENSITIVE_FIELDS: List[str] = [
        "password", "phone", "id_card", "bank_card", "email", "token"
    ]  # 敏感字段脱敏
    
    # 审计日志必选字段（企业级规范）
    AUDIT_LOG_MANDATORY_FIELDS: List[str] = [
        "audit_id", "timestamp", "user_id", "operation", "resource_type",
        "request_ip", "request_method", "request_path", "status"
    ]
    
    # 忽略审计的路径（健康检查等）
    AUDIT_LOG_IGNORE_PATHS: List[str] = ["/health", "/docs", "/redoc", "/openapi.json"]
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @field_validator("AUDIT_LOG_SIGN_SECRET")
    def validate_sign_secret(cls, v):
        if cls.AUDIT_LOG_SIGN_ENABLE and len(v) != 32:
            raise ValueError("AUDIT_LOG_SIGN_SECRET must be 32 bytes (256 bits) in production")
        return v

    @field_validator("AUDIT_LOG_IGNORE_PATHS", mode="before")
    def parse_ignore_paths(cls, v):
        if isinstance(v, str):
            return [path.strip() for path in v.split(",")]
        return v

# 全局配置实例
audit_settings = AuditLogSettings()

