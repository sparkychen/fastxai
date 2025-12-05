from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Literal, List, Optional
from pathlib import Path
import structlog

class LogSettings(BaseSettings):
    """日志专属配置（企业级精细化）"""
    # 基础配置
    LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    FORMAT: Literal["json", "console"] = "json"  # prod=json, dev=console
    ENABLE_ASYNC: bool = True                    # 生产环境开启异步日志
    ASYNC_BATCH_SIZE: int = 100                  # 异步批量写入大小
    ASYNC_FLUSH_INTERVAL: int = 1                # 异步刷新间隔（秒）
    
    # 日志文件配置（生产级轮转）
    FILE_ENABLE: bool = False
    FILE_PATH: Path = Path("/var/log/fastapi/app.log")
    FILE_ROTATION: str = "500MB"                 # 日志文件轮转大小
    FILE_RETENTION: str = "30 days"              # 日志留存周期
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

class Settings(BaseSettings):
    """应用总配置"""
    APP_NAME: str = "FastAPI-Structlog Enterprise"
    ENV: Literal["dev", "test", "prod"] = "prod"
    API_PREFIX: str = "/api/v1"
    
    # 日志配置嵌套
    LOG: LogSettings = Field(default_factory=LogSettings)
    
    # 分布式追踪
    TRACING_ENABLE: bool = True
    TRACING_SERVICE_NAME: str = "fastapi-enterprise"
    
    # CORS/安全
    CORS_ORIGINS: List[str] = ["https://app.enterprise.com"]

    # 多环境配置加载
    model_config = SettingsConfigDict(
        env_file=f".env.{ENV}",
        env_file_encoding="utf-8",
        case_sensitive=True,
        nested_mode="by_alias"  # 支持 LOG_LEVEL 形式的环境变量
    )

# 全局配置实例
settings = Settings()

# 动态调整日志配置（根据环境）
if settings.ENV == "dev":
    settings.LOG.FORMAT = "console"
    settings.LOG.LEVEL = "DEBUG"
    settings.LOG.ENABLE_ASYNC = False
    settings.LOG.FILE_ENABLE = False
elif settings.ENV == "prod":
    settings.LOG.FORMAT = "json"
    settings.LOG.LEVEL = "INFO"
    settings.LOG.ENABLE_ASYNC = True
    settings.LOG.FILE_ENABLE = True
