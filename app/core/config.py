# -*- coding: utf-8 -*-

import os
import sys
from enum import Enum
from pathlib import Path
from pydantic import PostgresDsn, MySQLDsn, field_validator
from typing import List, Literal, Optional, Dict, Set
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import EmailStr, SecretStr, Field
from cryptography.fernet import Fernet
from urllib.parse import quote_plus
from uuid_extensions import uuid7

class Settings(BaseSettings):
    
    APP_NAME: str = "FastXAI-Multi-agents-system"
    APP_VERSION: str = "0.0.2"
    ROOT_DIR: Path = Path(__file__).parent.parent.parent    
    ENV: Literal["dev", "dtaging", "prod"] = "dev"
    API_PREFIX: str = "/api/v1"

    # APP config
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 9968
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    ALLOWED_ORIGINS: List[str] = [f"http://{APP_HOST}:{APP_PORT}", f"http://localhost:{APP_PORT}"]

    DEBUG: bool = False if ENV != "prod" else True

    # 主库（写）DSN
    DB_MASTER_HOST: str = "localhost"
    DB_MASTER_PORT: int = 5432
    DB_MASTER_USER: str = "postgres"
    DB_MASTER_PASSWORD: str = quote_plus("postgresAdmin")
    DB_NAME: str = "fastxai"
    DB_MASTER_URL: str = f"postgresql+asyncpg://{DB_MASTER_USER}:{DB_MASTER_PASSWORD}@{DB_MASTER_HOST}:{DB_MASTER_PORT}/{DB_NAME}"
    DB_WRITE_DSN: List[str] = [DB_MASTER_URL]
    DB_READ_DSNS: List[str] = [DB_MASTER_URL]
    DB_ENABLE_RW_SEPARATION: bool = True
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", 20))           # 常驻连接数（CPU核心*2）
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", 10))     # 应急溢出连接
    DB_POOL_RECYCLE: int = int(os.getenv("DB_POOL_RECYCLE", 600))     # 连接回收（<数据库 wait_timeout）
    DB_POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", 30))    # 连接获取超时
    DB_POOL_PRE_PING: bool = True   # 连接健康检查
    DB_CHARSET: str = "utf8mb4"     # 字符集
    DB_POOL_USE_LIFO: bool = False if ENV != "prod" else True
    DB_ECHO: bool = False if ENV != "prod" else True          # 生产环境关闭SQL打印
    # 重试配置（故障恢复）
    DB_RETRY_MAX_ATTEMPTS: int = 5
    DB_RETRY_DELAY: float = 1.0
    DB_RETRY_BACKOFF: float = 2.0
    # SSL强制配置（生产环境必开）
    POSTGRES_SSL_MODE: Literal["require", "verify-ca", "verify-full"] = "verify-full"
    POSTGRES_SSL_ROOT_CERT: Path = Path("/etc/ssl/certs/root.crt")  # CA证书路径
    # 读写分离配置（企业级高可用）
    READ_WRITE_SEPARATION: bool = os.getenv("READ_WRITE_SEPARATION", "True").lower() == "true"
    POSTGRES_READ_HOSTS: List[str] = os.getenv("POSTGRES_READ_HOSTS", "").split(",") if os.getenv("POSTGRES_READ_HOSTS") else []

    DB_SLAVE_DELAY_THRESHOLD: float = 0.5  # 从库延迟阈值（秒）
    DB_SLAVE_DELAY_CHECK: bool = True      # 开启从库延迟检查


    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: str = os.getenv("REDIS_URL", f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")
    REDIS_PASSWORD: Optional[SecretStr] = None
    REDIS_CACHE_TTL_SECONDS: int = 300    # 用户信息# 异步连接池核心参数（与PostgreSQL max_connections匹配）
    

    # 日志文件配置（生产级轮转）
    # 基础配置
    # LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    FORMAT: Literal["json", "console"] = "json"  # prod=json, dev=console
    ENABLE_ASYNC: bool = True                    # 生产环境开启异步日志
    ASYNC_BATCH_SIZE: int = 100                  # 异步批量写入大小
    ASYNC_FLUSH_INTERVAL: int = 1                # 异步刷新间隔（秒）

    FILE_ENABLE: bool = False
    FILE_PATH: Path = Path("/var/log/fastapi/app.log")
    FILE_ROTATION: str = "256MB"                 # 日志文件轮转大小
    FILE_RETENTION: str = "90 days"              # 日志留存周期
    FILE_COMPRESSION: str = "gz"                 # 压缩格式

    # 上下文字段（必选/可选）
    REQUIRED_FIELDS: List[str] = ["request_id", "trace_id", "timestamp", "level", "logger"]
    OPTIONAL_FIELDS: List[str] = ["user_id", "tenant_id", "endpoint", "status_code", "duration"]
    
    # 敏感信息脱敏（字段+规则）
    SENSITIVE_FIELDS: List[str] = ["password", "phone", "email", "card_no"]
    SENSITIVE_MASK: str = "***"                  # 脱敏掩码
    SENSITIVE_RULES: dict = {
        "phone": r"(\d{3})\d{4}(\d{4})",         # 手机号脱敏：138****1234
        "email": r"(.{2}).*(@.*)",               # 邮箱脱敏：12****@xxx.com
        "card_no": r"(\d{4})\d{12}(\d{4})"       # 卡号脱敏：6226****1234
    }
    
    # 性能优化
    DISABLE_PROCESSORS: List[str] = []           # 禁用的处理器（如dev禁用耗时统计）
    CACHE_CONTEXT: bool = True                   # 缓存上下文（减少重复计算）

    # 审计日志级别与格式
    AUDIT_LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = LOG_LEVEL
    AUDIT_LOG_FORMAT: Literal["json", "console"] = "json"
    AUDIT_LOG_RETENTION_DAYS: int = 90  # 审计日志保留天数（合规要求）
    AUDIT_LOG_ASYNC: bool = True  # 异步写入（强制开启）
    AUDIT_LOG_BATCH_ENABLE: bool = True  # 批量写入
    AUDIT_LOG_BATCH_SIZE: int = 100  # 批量阈值
    AUDIT_LOG_BATCH_INTERVAL: float = 5.0  # 批量写入间隔（秒）
    AUDIT_LOG_CACHE_MAX_SIZE: int = 10000  # 内存缓存最大条数（防止OOM）
    AUDIT_LOG_REDIS_KEY: str = "audit:logs"    
    AUDIT_LOG_POSTGRES_TABLE: str = "audit_logs" # PostgreSQL 配置（持久化）    
    AUDIT_LOG_STORAGE_BACKENDS: List[Literal["file", "redis", "postgres", "es"]] = ["file", "redis", "postgres"] # 存储配置（分级存储）
    # 安全配置
    AUDIT_LOG_SIGN_ENABLE: bool = Field(
        default=True, 
        env="AUDIT_LOG_SIGN_ENABLE",
        description="是否开启审计日志签名（防篡改），生产环境必须为True"
    )
    AUDIT_LOG_SIGN_SECRET: bytes = Field(
        default=os.getenv("AUDIT_LOG_SIGN_SECRET", "0693630#b08770c4800096!d0$933968").encode(),  # 生产环境禁止硬编码，仅开发环境可临时兜底
        env="AUDIT_LOG_SIGN_SECRET",
        description="审计日志签名密钥（必须32字节，生产环境强制配置）"
    )
    AUDIT_LOG_SENSITIVE_FIELDS: List[str] = ["password", "phone", "id_card", "bank_card", "card_no", "email", "token" "access_token"]  # 敏感字段脱敏    
    # 审计日志必选字段（企业级规范）
    AUDIT_LOG_MANDATORY_FIELDS: List[str] = [
        "audit_id", "timestamp", "user_id", "operation", "resource_type",
        "request_ip", "request_method", "request_path", "status"
    ]    
    # 忽略审计的路径（健康检查等）
    AUDIT_LOG_IGNORE_PATHS: List[str] = ["/health", "/docs", "/redoc", "/openapi.json"]

    # ================= 审计日志配置 =================
    AUDIT_LOG_ENABLED: bool = True
    

    # Vector Stores
    VECTOR_STORE_TYPE: Literal["chroma", "qdrant", "milvus"] = "milvus"
    if VECTOR_STORE_TYPE == "qdrant":
        VECTOR_HOST: str = "localhost"
        VECTOR_PORT: int = 6333
    elif VECTOR_STORE_TYPE == "milvus":
        VECTOR_HOST: str = "localhost"
        VECTOR_PORT: int = 19530
    else:
        raise ValueError(f"(chroma) Not supported yet!")
    VECTOR_URL: str = f"http://{VECTOR_HOST}:{VECTOR_PORT}"
    VECTOR_API_KEY: Optional[str] = None


    SENTRY_DNS: str = ""
    

    # Authentication
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # JWT 配置（企业级非对称加密）
    JWT_PRIVATE_KEY_PATH: Path = Path("keys/private.pem")
    JWT_PUBLIC_KEY_PATH: Path = Path("keys/public.pem")
    # JWT_ALGORITHM: str = "RS256"
    JWT_ALGORITHM: str = "HS256"
    # JWT_ALGORITHM: str = "HS512"  # 强算法
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_REFRESH_TOKEN_ROTATION: bool = True  # 刷新令牌轮换（防止重放）
    JWT_BLACKLIST_ENABLED: bool = True  # 令牌黑名单
    JWT_BLACKLIST_TTL_SECONDS: int = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60  # 黑名单超时
    JWT_SECRET_KEY: str = Field(
        default="dev-only-jwt-secret-32bytes-12345678",  # 开发兜底
        env="JWT_SECRET_KEY",  # 修复：闭合引号
        description="JWT签名密钥（生产环境必须≥32字节）"
    )
    JWT_AUDIENCE: str = "fastapi:auth"
    JWT_ISSUER: str = "secure-api"
    JWT_BLACKLIST_TOKEN_TYPE: Literal["access", "refresh", "both"] = "both"

    # MFA配置
    MFA_REQUIRED: bool = True  # 生产环境强制MFA
    MFA_ISSUER_NAME: str = "FastXAI-MFA"
    MFA_ISSUER: str = "YourApp"
    MFA_RATE_LIMIT: int = 5    # 每分钟最大尝试次数
    MFA_BACKUP_CODES: int = 10 # 备份代码数量
    MFA_VALID_WINDOW: int = 1  # TOTP验证窗口（±30秒，避免网络延迟）
    MFA_MAX_FAILED_ATTEMPTS: int = 5  # 最大失败次数
    MFA_LOCK_DURATION_MINUTES: int = 15  # 锁定时长（分钟）
    
    # 密码策略（企业级强化）
    PASSWORD_MIN_LENGTH: int = 9
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_HISTORY_SIZE: int = 5
    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 30
    PASSWORD_REQUIRE_SPECIAL: bool = True
    ARGON2_MEMORY_COST: int = 102400  # Argon2 内存成本（越高越安全）
    ARGON2_TIME_COST: int = 3         # 时间成本
    ARGON2_PARALLELISM: int = 4       # 并行度
    PASSWORD_HASH_ALGORITHM: str = "scrypt"
    PASSWORD_BCRYPT_ROUNDS: int = 14  # 计算强度（越高越安全，性能需平衡）
        
    # 速率限制（防暴力破解）
    RATE_LIMIT_LOGIN: str = "5/minute"  # 登录接口限制
    RATE_LIMIT_REGISTER: str = "10/hour" # 注册接口限制
    RATE_LIMIT_RESET_PASSWORD: str = "3/hour" # 密码重置限制

    # ================= 速率限制配置 =================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_STORAGE_URL: str = "redis://redis:6379/0"  # 分布式限流存储
    RATE_LIMIT_DEFAULT: str = "100/minute"  # 默认限流
    RATE_LIMIT_AUTH: str = "300/minute"  # 认证接口限流
    RATE_LIMIT_ADMIN: str = "500/minute"  # 管理员接口限流
    
    # ================= 数据安全配置 =================
    ENCRYPTION_ALGORITHM: str = "AES-256-GCM"  # 对称加密算法
    ENCRYPTION_KEY: bytes = os.getenv("ENCRYPTION_KEY", "mM93630$b08770c480096#@d0$933968").encode()  # 32字节密钥
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
    # CORS安全配置（严格限制）
    CORS_ORIGINS: List[str] = []  # 生产环境显式指定，禁止通配符
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    CORS_ALLOW_HEADERS: List[str] = ["Authorization", "Content-Type", "X-Request-ID"]

    # 配置验证
    @field_validator("SECRET_KEY", mode="before", check_fields=False) # mode="before" 表示验证原始值
    def validate_secret_key(cls, v):
        if not v and cls.ENV == "prod":
            raise ValueError("SECRET_KEY must be set in production environment")
        return v

    @field_validator("ENCRYPTION_KEY", mode="before")
    def validate_encryption_key(cls, v):
        if len(v) != 32 and cls.ENV == "prod":
            raise ValueError("ENCRYPTION_KEY must be 32 bytes (256 bits) in production")
        return v

    @field_validator("ALLOWED_HOSTS", "CORS_ORIGINS", mode="before", check_fields=False)
    def parse_list(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",")]
        return v

    @property
    def is_production(self) -> bool:
        return self.ENV == "prod"

    @property
    def jwt_private_key(self) -> str:
        """加载RSA私钥（生产级：从密钥管理系统读取）"""
        return self.JWT_PRIVATE_KEY_PATH.read_text() if self.JWT_PRIVATE_KEY_PATH.exists() else ""

    @property
    def jwt_public_key(self) -> str:
        """加载RSA公钥"""
        return self.JWT_PUBLIC_KEY_PATH.read_text() if self.JWT_PUBLIC_KEY_PATH.exists() else ""

    # OpenAI
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_API_BASE: Optional[str] = None

    # MCP
    MCP_SERVER_HOST: str = "localhost"
    MCP_SERVER_PORT: int = 8080  


    # API安全
    API_RATE_LIMIT: str = "100/minute"
    CORS_ORIGINS: List[str] = []
    TRUSTED_HOSTS: List[str] = []
    SECURE_COOKIES: bool = True
    SESSION_TIMEOUT_MINUTES: int = 60

    # CORS安全配置（严格限制）
    CORS_ORIGINS: List[str] = []  # 生产环境显式指定，禁止通配符
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    CORS_ALLOW_HEADERS: List[str] = ["Authorization", "Content-Type", "X-Request-ID"]
      
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
    # 异步连接池核心参数（与PostgreSQL max_connections匹配）
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", 20))          # 常驻连接数（CPU核心数*2）
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", 40))    # 应急溢出连接数
    DB_POOL_RECYCLE: int = int(os.getenv("DB_POOL_RECYCLE", 280))   # 连接回收时间（< 300秒超时）
    DB_POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", 30))    # 连接获取超时
    DB_PRE_PING: bool = True                                        # 连接前健康检查
    # 监控配置
    SECURITY_EVENT_LOG_LEVEL: str = "INFO"
    ENABLE_SECURITY_AUDIT: bool = True

    @field_validator("AUDIT_LOG_SIGN_SECRET", mode="after")
    def validate_sign_secret(cls, v: bytes, info):
        enable = info.data.get("AUDIT_LOG_SIGN_ENABLE", False)
        if enable and len(v) != 32:
            raise ValueError("AUDIT_LOG_SIGN_SECRET must be 32 bytes (256 bits) in production")
        return v

    @field_validator("AUDIT_LOG_IGNORE_PATHS", mode="before")
    def parse_ignore_paths(cls, v):
        if isinstance(v, str):
            return [path.strip() for path in v.split(",")]
        return v
    
    @field_validator("JWT_SECRET_KEY", "ENCRYPTION_KEY", mode="before")
    def validate_key_length(cls, v):
        if len(v) < 32:
            raise ValueError("密钥长度必须至少32个字符")
        return v
    
    @field_validator("CORS_ORIGINS", mode="before")
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @field_validator("POSTGRES_DSN", mode="before", check_fields=False)
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
   

    # 生产级配置加载（优先级：环境变量 > .env.prod）
    model_config = SettingsConfigDict(
        env_file=f".env.{ENV}",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        frozen=True   # 配置冻结，防止运行时篡改（安全增强）
    )


class KeyManagementService:
    """密钥管理服务"""    
    def __init__(self):
        self.fernet = Fernet(Settings().ENCRYPTION_KEY.decode())
    
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


settings = Settings()
# key_manager = KeyManagementService()

# # 动态调整日志配置（根据环境）
# if settings.ENV == "dev":
#     settings.LOG.FORMAT = "console"
#     settings.LOG.LEVEL = "DEBUG"
#     settings.LOG.ENABLE_ASYNC = False
#     settings.LOG.FILE_ENABLE = False
# elif settings.ENV == "prod":
#     settings.LOG.FORMAT = "json"
#     settings.LOG.LEVEL = "INFO"
#     settings.LOG.ENABLE_ASYNC = True
#     settings.LOG.FILE_ENABLE = True