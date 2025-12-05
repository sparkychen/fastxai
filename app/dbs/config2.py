# -*- coding: utf-8 -*-

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import PostgresDsn, field_validator
from typing import Optional, Literal, List
from pathlib import Path
import os

class DatabaseSettings(BaseSettings):
    """企业级PostgreSQL异步配置"""
    # 基础连接信息
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "app_user")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")  # 生产环境从密钥管理服务获取
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "postgres")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", 5432))
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "enterprise_db")
    POSTGRES_DSN: Optional[PostgresDsn] = None

    # SSL强制配置（生产环境必开）
    POSTGRES_SSL_MODE: Literal["require", "verify-ca", "verify-full"] = "verify-full"
    POSTGRES_SSL_ROOT_CERT: Path = Path("/etc/ssl/certs/root.crt")  # CA证书路径

    # 异步连接池核心参数（与PostgreSQL max_connections匹配）
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", 20))          # 常驻连接数（CPU核心数*2）
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", 40))    # 应急溢出连接数
    DB_POOL_RECYCLE: int = int(os.getenv("DB_POOL_RECYCLE", 280))   # 连接回收时间（< 300秒超时）
    DB_POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", 30))    # 连接获取超时
    DB_PRE_PING: bool = True                                        # 连接前健康检查

    # 读写分离配置（企业级高可用）
    READ_WRITE_SEPARATION: bool = os.getenv("READ_WRITE_SEPARATION", "True").lower() == "true"
    POSTGRES_READ_HOSTS: List[str] = os.getenv("POSTGRES_READ_HOSTS", "").split(",") if os.getenv("POSTGRES_READ_HOSTS") else []

    # 重试配置（故障恢复）
    DB_RETRY_MAX_ATTEMPTS: int = 5
    DB_RETRY_DELAY: float = 1.0
    DB_RETRY_BACKOFF: float = 2.0

    db_slave_delay_threshold: float = 0.5  # 从库延迟阈值（秒）
    db_slave_delay_check: bool = True      # 开启从库延迟检查

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @field_validator("POSTGRES_DSN", mode="before")
    def assemble_async_dsn(cls, v, values):
        """组装asyncpg驱动的DSN（含SSL）"""
        if isinstance(v, str):
            return v
        
        ssl_params = f"sslmode={values.data['POSTGRES_SSL_MODE']}&sslrootcert={values.data['POSTGRES_SSL_ROOT_CERT']}"
        return PostgresDsn.build(
            scheme="postgresql+asyncpg",  # 异步驱动标识
            username=values.data["POSTGRES_USER"],
            password=values.data["POSTGRES_PASSWORD"],
            host=values.data["POSTGRES_HOST"],
            port=str(values.data["POSTGRES_PORT"]),
            path=f"/{values.data['POSTGRES_DB']}?{ssl_params}",
        )

    @property
    def sync_dsn(self) -> str:
        """同步DSN（仅用于Alembic迁移）"""
        return PostgresDsn.build(
            scheme="postgresql+psycopg2",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=str(self.POSTGRES_PORT),
            path=f"/{self.POSTGRES_DB}",
        )

# 全局配置实例
db_settings = DatabaseSettings()



class DBSettings:
    # 多主库DSN（主库+备用主库）
    db_write_dsns: List[PostgresDsn] = [
        "postgresql+asyncpg://user:pass@master-db:5432/db",
        "postgresql+asyncpg://user:pass@backup-master-db:5432/db"
    ]
    # 多从库DSN
    db_read_dsns: List[PostgresDsn] = [
        "postgresql+asyncpg://user:pass@slave1-db:5432/db",
        "postgresql+asyncpg://user:pass@slave2-db:5432/db"
    ]
    db_enable_rw_separation: bool = True
    # 连接池配置（分场景LIFO/FIFO）
    db_pool_use_lifo: bool = db_settings.env == "production"  # 生产=LIFO，开发=FIFO
    db_pool_size: int = 20
    db_max_overflow: int = 40
    db_pool_recycle: int = 280
    db_connect_timeout: int = 10
    db_charset: str = "utf8mb4"
    db_echo: bool = False
    env: Literal["development", "production"] = "production"

