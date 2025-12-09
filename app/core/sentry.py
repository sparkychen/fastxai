# -*- coding: utf-8 -*-

import os
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.starlette import StarletteIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.aiohttp import AioHttpIntegration
from sentry_sdk import add_breadcrumb, capture_exception, capture_message
from app.core.config import settings
import asyncio
import aiohttp
from sentry_sdk.transport import Transport
from sentry_sdk.envelope import Envelope
from typing import Optional
from structlog.contextvars import merge_contextvars
# 初始化日志
from app.core.logger import logger

def sentry_structlog_processor(logger, method_name, event_dict):
    """
    手动实现 Structlog → Sentry 联动：
    - INFO/WARN → Sentry 面包屑
    - ERROR/CRITICAL → Sentry 事件 + 面包屑
    """
    # 提取日志元数据
    log_level = event_dict.get("level", "info").upper()
    log_message = event_dict.get("event", "")
    context = {k: v for k, v in event_dict.items() if k not in ["event", "level", "timestamp"]}

    # 1. 过滤无意义日志（如健康检查）
    if event_dict.get("path") == "/health" and log_level == "INFO":
        return event_dict

    # 2. 生产环境采样（减少面包屑数量）
    if ENVIRONMENT == "production":
        # INFO 日志仅 10% 作为面包屑
        if log_level == "INFO" and not sentry_sdk.Hub.current.scope.transaction:
            import random
            if random.random() > 0.1:
                return event_dict
        # WARNING 日志仅 50% 作为面包屑
        elif log_level == "WARNING" and random.random() > 0.5:
            return event_dict

    # 3. 添加面包屑（所有级别，除采样过滤的）
    add_breadcrumb(
        message=log_message,
        level=log_level.lower(),
        category=logger.name,
        data=context,
        timestamp=event_dict.get("timestamp")
    )

    # 4. ERROR/CRITICAL 级日志直接上报为 Sentry 事件
    if log_level in ["ERROR", "CRITICAL"]:
        # 有异常栈则上报异常，否则上报消息
        if "exc_info" in event_dict and event_dict["exc_info"]:
            capture_exception(
                event_dict["exc_info"],
                extra=context,
                level=log_level.lower()
            )
        else:
            capture_message(
                log_message,
                level=log_level.lower(),
                extra=context
            )

    return event_dict

class AsyncTransport(Transport):
    """高性能异步传输层"""
    
    def __init__(self, options=None):
        super().__init__(options)
        self._session: Optional[aiohttp.ClientSession] = None
        self._queue = asyncio.Queue(maxsize=1000)  # 控制队列大小
        self._worker_task = None
        self._start_worker()
    
    def _start_worker(self):
        """启动异步工作线程"""
        self._worker_task = asyncio.create_task(self._worker())
    
    async def _worker(self):
        """异步工作线程"""
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10)
        ) as session:
            self._session = session
            while True:
                try:
                    envelope = await self._queue.get()
                    if envelope is None:  # 关闭信号
                        break
                    await self._send_envelope(envelope)
                except Exception as e:
                    logger.error(f"Sentry 异步发送失败: {e}")
    
    async def _send_envelope(self, envelope: Envelope):
        """发送 envelope"""
        if not self._session:
            return
        
        try:
            # 序列化 envelope
            body = envelope.serialize()
            
            async with self._session.post(
                self._get_dsn().to_url(),
                data=body,
                headers={"Content-Type": "application/x-sentry-envelope"}
            ) as response:
                if response.status != 200:
                    logger.warning(f"Sentry 响应异常: {response.status}")
        except Exception as e:
            logger.error(f"发送 Sentry 数据失败: {e}")
    
    def capture_envelope(self, envelope: Envelope):
        """捕获 envelope - 异步非阻塞"""
        try:
            # 非阻塞放入队列
            self._queue.put_nowait(envelope)
        except asyncio.QueueFull:
            logger.warning("Sentry 队列已满，丢弃事件")
    
    async def close(self):
        """优雅关闭"""
        if self._worker_task:
            await self._queue.put(None)  # 发送关闭信号
            await self._worker_task


def configure_sentry():
    """配置 Sentry SDK - 企业级优化"""    
    if not settings.SENTRY_DSN:
        logger.warning("SENTRY_DSN 未配置，Sentry 监控已禁用")
        return False
    
    try:
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            #dsn="https://your-dsn-here@sentry.io/123456", #初始化Sentry（生产环境必须配置DSN)
            integrations=[
                FastApiIntegration(transaction_style="url"),
                StarletteIntegration(transaction_style="url"),
                sentry_structlog_processor(),
                SqlalchemyIntegration(),
                RedisIntegration(),
                AioHttpIntegration(),
            ],
            # 环境配置
            environment=settings.ENV,
            release=settings.SENTRY_RELEASE,
            # 性能监控配置
            traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
            profiles_sample_rate=settings.SENTRY_PROFILES_SAMPLE_RATE,
            # 异步配置
            transport=AsyncTransport,  # 自定义异步传输
            # 采样配置
            sample_rate=1.0,  # 错误事件采样率
            # 性能优化
            max_breadcrumbs=50,  # 最大面包屑数量
            debug=settings.SENTRY_DEBUG,
            # 隐私安全
            send_default_pii=settings.SENTRY_SEND_DEFAULT_PII,
            # 过滤敏感信息
            before_send=before_send_filter,
            before_send_transaction=before_send_transaction,
            # 进程池配置（高性能）
            _experiments={
                "continuous_profiling_auto_start": True,
                "profiles_sample_rate": 0.1,
            }
        )
        logger.info("Sentry SDK 初始化成功")
        return True
    except Exception as e:
        logger.error(f"Sentry SDK 初始化失败: {e}")
        return False

def before_send_filter(event, hint):
    """过滤敏感信息"""
    # 移除请求头中的敏感信息
    if "request" in event and "headers" in event["request"]:
        sensitive_headers = ["authorization", "cookie", "x-api-key"]
        for header in sensitive_headers:
            if header in event["request"]["headers"]:
                event["request"]["headers"][header] = "[FILTERED]"
    
    # 自定义过滤逻辑
    if "logentry" in event and "message" in event["logentry"]:
        message = event["logentry"]["message"]
        # 过滤密码等敏感信息
        if "password" in message.lower():
            event["logentry"]["message"] = "[敏感信息已过滤]"
    
    return event

def before_send_transaction(event, hint):
    """过滤性能事务中的敏感信息"""
    # 可以在这里添加性能数据过滤逻辑
    return event


##############
# 环境标识（通过环境变量注入，企业级部署规范）
ENVIRONMENT = settings.ENV
# Sentry DSN（不同环境配置不同，生产需加密存储）
SENTRY_DSN = os.getenv("SENTRY_DSN", "")
# 服务名/版本（关联代码版本，便于定位问题）
SERVICE_NAME = "fastapi-enterprise-service"
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")

# 采样率配置（企业级性能优化核心）
SENTRY_CONFIG = {
    # 基础配置
    "dsn": SENTRY_DSN,
    "environment": ENVIRONMENT,
    "release": f"{SERVICE_NAME}@{SERVICE_VERSION}",
    "server_name": os.getenv("HOSTNAME", "unknown"),  # 容器/服务器标识
    # 性能优化：异步传输（避免阻塞FastAPI请求）
    "transport": AsyncTransport,
    # 批量上报（减少网络请求，默认100条批量，可根据QPS调整）
    "send_default_pii": False,  # 禁止传输PII（个人敏感信息），合规要求
    "max_queue_length": 1000,   # 最大队列长度（避免内存溢出）
    "shutdown_timeout": 5,      # 进程退出时等待上报完成的时间（秒）
    # 采样控制（核心高性能点：减少不必要的上报）
    "traces_sample_rate": {     # 性能追踪采样率（按环境区分）
        "development": 1.0,     # 开发环境全量采样
        "staging": 0.5,         # 测试环境50%采样
        "production": 0.1       # 生产环境10%采样（QPS高时可降至0.05）
    }.get(ENVIRONMENT, 0.1),
    "traces_sampler": lambda sampling_context: (
        0.0  # 排除健康检查接口
        if sampling_context.get("transaction_context", {}).get("name") == "GET /health"
        else (0.5 if ENVIRONMENT == "production" else 1.0)  # payment 接口高采样
        if "payment" in sampling_context.get("transaction_context", {}).get("name", "")
        else SENTRY_CONFIG["traces_sample_rate"]  # 其他接口用默认采样率
    ),
    # 错误采样（生产环境建议100%，确保不遗漏错误）
    "sample_rate": 1.0,
    # 集成配置（仅启用必要集成，减少开销）
    "integrations": [
        # FastAPI/Starlette 集成（自动捕获请求/响应上下文）
        StarletteIntegration(
            transaction_style="endpoint"  # 事务名用接口端点（如GET /api/v1/user）
        ),
        FastApiIntegration(
            transaction_style="endpoint"
        ),
        # AioHttp 集成（捕获异步HTTP请求异常，如调用外部API）
        AioHttpIntegration(),
        # 可选：如需监控Redis/MongoDB，添加对应集成（按需启用，避免冗余）
        RedisIntegration(),
        # MongoIntegration(),
    ],
    # 敏感信息过滤（企业级合规核心）
    "before_send": lambda event, hint: filter_sensitive_data(event, hint),
    "before_send_transaction": lambda event, hint: filter_sensitive_data(event, hint),
}

def filter_sensitive_data(event: dict, hint: dict) -> dict:
    """过滤事件中的敏感信息（密码、手机号、身份证等）"""
    # 1. 过滤请求体中的敏感字段
    if "request" in event and "data" in event["request"]:
        request_data = event["request"]["data"]
        sensitive_fields = ["password", "phone", "id_card", "token", "secret"]
        for field in sensitive_fields:
            if field in request_data:
                request_data[field] = "[FILTERED]"
        event["request"]["data"] = request_data
    
    # 2. 过滤响应中的敏感字段
    if "response" in event and "data" in event["response"]:
        response_data = event["response"]["data"]
        for field in sensitive_fields:
            if field in response_data:
                response_data[field] = "[FILTERED]"
        event["response"]["data"] = response_data
    
    # 3. 过滤自定义标签中的敏感信息（如有）
    if "tags" in event:
        event["tags"] = {k: v if "secret" not in k else "[FILTERED]" for k, v in event["tags"].items()}
    
    return event

def init_sentry() -> None:
    """初始化Sentry（仅在DSN存在时启用，避免开发环境报错）"""
    if not SENTRY_DSN:
        print(f"[Sentry] DSN not found, skip initialization (env: {ENVIRONMENT})")
        return
    
    # 初始化Sentry
    sentry_sdk.init(**SENTRY_CONFIG)
    print(f"[Sentry] initialized successfully (env: {ENVIRONMENT}, service: {SERVICE_NAME})")