import time
import sys
import re
from typing import Dict, Any
import structlog
from structlog.processors import (
    TimeStamper,
    StackInfoRenderer,
    format_exc_info,
    JSONRenderer,
    KeyValueRenderer
)
from structlog.stdlib import (
    add_log_level,
    filter_by_level,
    BoundLogger,
    get_logger
)
from structlog.threadlocal import wrap_dict, ThreadLocalDict
from loguru import logger as loguru_logger
from app.core.config import settings
from app.utils.async_logger import AsyncLogProcessor

# ========== 1. 性能优化：上下文缓存（ThreadLocal） ==========
# 线程本地存储上下文，避免重复绑定
thread_local_context = ThreadLocalDict()
structlog.configure(
    cache_logger_on_first_use=True,  # 缓存Logger实例（性能提升30%+）
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=BoundLogger,
)

# ========== 2. 核心处理器（企业级结构化） ==========
def get_processors() -> list:
    """根据配置动态生成处理器链（高性能）"""
    processors = [
        # 基础处理器（必选）
        filter_by_level,  # 按级别过滤日志
        add_log_level,    # 添加日志级别字段
        TimeStamper(fmt="iso", key="timestamp"),  # ISO格式时间戳
        StackInfoRenderer(),  # 栈信息（仅ERROR级别）
        format_exc_info,      # 异常栈信息
    ]

    # 上下文字段过滤（保留必填/可选字段）
    def filter_fields(_, __, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """过滤并排序日志字段（规范输出）"""
        filtered = {}
        # 保留必填字段
        for field in settings.LOG.REQUIRED_FIELDS:
            filtered[field] = event_dict.get(field, "")
        # 保留可选字段（存在则添加）
        for field in settings.LOG.OPTIONAL_FIELDS:
            if field in event_dict:
                filtered[field] = event_dict[field]
        # 保留事件内容
        filtered["event"] = event_dict.get("event", "")
        # 敏感信息脱敏
        for field in settings.LOG.SENSITIVE_FIELDS:
            if field in filtered and filtered[field]:
                filtered[field] = mask_sensitive(field, filtered[field])
        return filtered

    processors.append(filter_fields)

    # 异步日志处理器（生产级）
    if settings.LOG.ENABLE_ASYNC and "async" not in settings.LOG.DISABLE_PROCESSORS:
        processors.append(
            AsyncLogProcessor(
                batch_size=settings.LOG.ASYNC_BATCH_SIZE,
                flush_interval=settings.LOG.ASYNC_FLUSH_INTERVAL
            )
        )

    # 格式渲染器（多环境适配）
    if settings.LOG.FORMAT == "json":
        processors.append(JSONRenderer(sort_keys=True))  # JSON格式（便于解析）
    else:
        # 控制台格式（开发环境友好）
        processors.append(
            KeyValueRenderer(
                key_order=["timestamp", "level", "request_id", "event"],
                fmt="[{timestamp}] [{level}] [{request_id}] {event}",
            )
        )

    # 禁用指定处理器
    processors = [p for p in processors if p.__name__ not in settings.LOG.DISABLE_PROCESSORS]

    return processors

# ========== 3. 敏感信息脱敏工具 ==========
def mask_sensitive(field: str, value: Any) -> str:
    """脱敏敏感字段（支持正则/简单掩码）"""
    if not value or not isinstance(value, str):
        return value
    # 正则脱敏（如手机号/邮箱）
    if field in settings.LOG.SENSITIVE_RULES:
        pattern = settings.LOG.SENSITIVE_RULES[field]
        return re.sub(pattern, r"\1****\2", value)
    # 简单掩码（如密码）
    return settings.LOG.SENSITIVE_MASK

# ========== 4. 日志文件轮转配置（生产级） ==========
def configure_file_logger():
    """配置Loguru日志轮转（替代structlog文件输出，性能更高）"""
    if not settings.LOG.FILE_ENABLE:
        return
    # 创建日志目录
    settings.LOG.FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    # 添加文件处理器
    loguru_logger.add(
        settings.LOG.FILE_PATH,
        rotation=settings.LOG.FILE_ROTATION,
        retention=settings.LOG.FILE_RETENTION,
        compression=settings.LOG.FILE_COMPRESSION,
        format="{message}",  # structlog已处理格式，直接输出
        level=settings.LOG.LEVEL,
        enqueue=True,  # 异步写入（无锁）
    )

# ========== 5. 全局Logger初始化 ==========
def init_logger() -> structlog.BoundLogger:
    """初始化企业级Logger（高性能）"""
    # 配置structlog处理器链
    structlog.configure(
        processors=get_processors(),
        context_class=wrap_dict(thread_local_context),  # 线程本地上下文
    )
    # 配置文件日志
    configure_file_logger()
    # 获取基础Logger
    logger = get_logger(settings.APP_NAME)
    # 设置全局日志级别
    structlog.configure(logger_factory=lambda name: loguru_logger.bind(name=name))
    return logger

# ========== 6. 上下文绑定工具（企业级） ==========
def bind_context(**kwargs):
    """绑定上下文到线程本地存储（高性能）"""
    if settings.LOG.CACHE_CONTEXT:
        thread_local_context.update(kwargs)

def unbind_context(*keys):
    """解绑上下文（避免内存泄漏）"""
    if keys:
        for key in keys:
            thread_local_context.pop(key, None)
    else:
        thread_local_context.clear()

def get_context() -> Dict[str, Any]:
    """获取当前上下文（缓存）"""
    return dict(thread_local_context)

# 全局Logger实例
logger = init_logger()
