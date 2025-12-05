# -*- coding: utf-8 -*-
# doubao

import structlog
import logging
from logging.handlers import RotatingFileHandler
import asyncio
from pathlib import Path
from fastapi_structlog import setup_logging as setup_fastapi_structlog
from app.core.config import audit_settings

# 确保日志目录存在
LOG_DIR = audit_settings.ROOT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ========== 核心处理器配置 ==========
def configure_structlog():
    """初始化结构化日志（结合fastapi-structlog）"""
    # 基础处理器链
    processors = [
        # 1. 上下文变量合并（request_id、user_id等）
        structlog.contextvars.merge_contextvars,
        # 2. 添加日志级别
        structlog.processors.add_log_level,
        # 3. 添加时间戳（ISO格式）
        structlog.processors.TimeStamper(fmt="iso", key="timestamp"),
        # 4. 异常格式化
        structlog.processors.format_exc_info,
        # 5. 脱敏敏感字段
        structlog.processors.JSONRenderer(serializer=json_serializer),
    ]

    # 生产环境：JSON格式 + 轮转文件
    if audit_settings.ENVIRONMENT == "production":
        # 配置根日志
        logging.basicConfig(
            level=getattr(logging, audit_settings.AUDIT_LOG_LEVEL),
            handlers=[
                RotatingFileHandler(
                    LOG_DIR / "audit.log",
                    maxBytes=100 * 1024 * 1024,  # 100MB per file
                    backupCount=audit_settings.AUDIT_LOG_RETENTION_DAYS,
                    encoding="utf-8",
                ),
                logging.StreamHandler(),  # 同时输出到控制台（便于排查）
            ],
        )

        structlog.configure(
            processors=processors,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,  # 性能优化：缓存logger
        )
    # 开发环境：控制台友好格式
    else:
        processors.append(structlog.dev.ConsoleRenderer())
        structlog.configure(
            processors=processors,
            logger_factory=structlog.stdlib.LoggerFactory(),
        )

    # 集成fastapi-structlog（自动绑定request_id等上下文）
    setup_fastapi_structlog(
        app_name=audit_settings.APP_NAME,
        log_level=audit_settings.AUDIT_LOG_LEVEL,
        json_logs=audit_settings.AUDIT_LOG_FORMAT == "json",
        add_process_time=True,  # 添加接口处理时间
        add_request_id=True,    # 添加唯一request_id
    )

# ========== 自定义JSON序列化器（脱敏+兼容） ==========
import json
from datetime import datetime, UUID
from app.core.audit import mask_sensitive_data  # 后续定义脱敏函数

def json_serializer(obj, *, default=None):
    """自定义JSON序列化器：处理特殊类型 + 脱敏"""
    # 处理UUID
    if isinstance(obj, UUID):
        return str(obj)
    # 处理datetime
    if isinstance(obj, datetime):
        return obj.isoformat()
    # 脱敏敏感数据
    if isinstance(obj, dict):
        return mask_sensitive_data(obj)
    # 默认序列化
    return default(obj) if default else json.JSONEncoder.default(obj)

# ========== 审计日志Logger实例 ==========
def get_audit_logger() -> structlog.BoundLogger:
    """获取审计日志专用Logger"""
    return structlog.get_logger("audit")

# 初始化日志配置
configure_structlog()
audit_logger = get_audit_logger()
