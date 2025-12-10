# -*- coding: utf-8 -*-

import os
import sys
import time
from typing import Any, Dict, Optional
import orjson
import structlog
import queue
import asyncio
import threading
from structlog.stdlib import get_logger
from loguru import logger as loguru_logger
from app.core.config import settings
from structlog.threadlocal import wrap_dict
from enum import Enum
from contextvars import ContextVar
from uuid import uuid4
from datetime import datetime
from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
from app.core.context import get_request_context

# 使用 contextvars 替代 ThreadLocalDict
request_id_var: ContextVar[str] = ContextVar("request_id", default="")
trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")
user_id_var: ContextVar[str] = ContextVar("user_id", default="")
session_id_var: ContextVar[str] = ContextVar("session_id", default="")
client_ip_var: ContextVar[str] = ContextVar("client_ip", default="")
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")
endpoint_var: ContextVar[str] = ContextVar("endpoint", default="")


# class AuditEventType(Enum):
#     AUTHENTICATION = "authentication"
#     AUTHORIZATION = "authorization" 
#     DATA_ACCESS = "data_access"
#     DATA_MODIFICATION = "data_modification"
#     CONFIG_CHANGE = "config_change"
#     SYSTEM_EVENT = "system_event"
#     SECURITY_EVENT = "security_event"

# class AuditResultStatus(Enum):
#     SUCCESS = "success"
#     FAILURE = "failure"
#     DENIED = "denied"

# class AuditContext:
#     """审计上下文管理器"""
    
#     def __init__(self, 
#                  request_id: Optional[str] = None,
#                  user_id: Optional[str] = None,
#                  session_id: Optional[str] = None,
#                  client_ip: Optional[str] = None,
#                  correlation_id: Optional[str] = None):
#         self.request_id = request_id or str(uuid4())
#         self.user_id = user_id
#         self.session_id = session_id
#         self.client_ip = client_ip
#         self.correlation_id = correlation_id or str(uuid4())
#         self._token = None
    
#     def __enter__(self):
#         """进入上下文时设置变量"""
#         if self.request_id:
#             self._request_token = request_id_var.set(self.request_id)
#         if self.user_id:
#             self._user_token = user_id_var.set(self.user_id)
#         if self.session_id:
#             self._session_token = session_id_var.set(self.session_id)
#         if self.client_ip:
#             self._client_ip_token = client_ip_var.set(self.client_ip)
#         if self.correlation_id:
#             self._correlation_token = correlation_id_var.set(self.correlation_id)
#         return self
    
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         """退出上下文时恢复变量"""
#         if hasattr(self, '_request_token'):
#             request_id_var.reset(self._request_token)
#         if hasattr(self, '_user_token'):
#             user_id_var.reset(self._user_token)
#         if hasattr(self, '_session_token'):
#             session_id_var.reset(self._session_token)
#         if hasattr(self, '_client_ip_token'):
#             client_ip_var.reset(self._client_ip_token)
#         if hasattr(self, '_correlation_token'):
#             correlation_id_var.reset(self._correlation_token)

# class AuditLogger:
#     """高性能审计日志记录器"""
    
#     def __init__(self):
#         self._logger = structlog.get_logger("audit")
    
#     def log_event(
#         self,
#         event_type: AuditEventType,
#         resource: str,
#         action: str,
#         status: AuditResultStatus,
#         details: Optional[Dict[str, Any]] = None,
#         user_id: Optional[str] = None,
#         client_ip: Optional[str] = None,
#         metadata: Optional[Dict[str, Any]] = None
#     ) -> None:
#         """记录审计事件"""
        
#         # 使用上下文变量中的值作为默认值
#         current_user_id = user_id or user_id_var.get()
#         current_client_ip = client_ip or client_ip_var.get()
        
#         audit_record = {
#             "timestamp": datetime.utcnow().isoformat() + "Z",
#             "event_id": str(uuid4()),
#             "event_type": event_type.value,
#             "resource": resource,
#             "action": action,
#             "status": status.value,
#             "request_id": request_id_var.get(),
#             "session_id": session_id_var.get(),
#             "user_id": current_user_id,
#             "client_ip": current_client_ip,
#             "correlation_id": correlation_id_var.get(),
#             "details": details or {},
#             "metadata": metadata or {},
#             "environment": os.getenv("ENVIRONMENT", "dev"),
#             "service_name": "fastapi-audit-service",
#             "version": "1.0.0"
#         }
        
#         # 使用适当日志级别
#         log_level = logging.INFO if status == AuditResultStatus.SUCCESS else logging.WARNING
#         self._logger.log(log_level, "audit_event", **audit_record)

def structlog_context_processor(_, __, event_dict):
    """structlog处理器：自动注入请求上下文（兼容非请求场景）"""
    ctx = get_request_context()
    # 兜底默认值（无上下文时用空字符串，避免KeyError）
    ctx = get_request_context()
    default_ctx = {
        "request_id": "",
        "user_id": "",
        "trace_idd": "",
        "endpoint": "",
        "correlation_id": "",
        "session_id": "",
        "client_ip": "",
    }
    if ctx:
        ctx_dict = {
            "request_id": ctx.request_id,
            "user_id": ctx.user_id or "",
            "client_ip": ctx.client_ip or "",
            "trace_idd": "",
            "endpoint": ctx.path or "",
            "correlation_id": "",
            "session_id": "",
        }
        event_dict.update({**default_ctx, **ctx_dict})
    else:
        event_dict.update(default_ctx)
    return event_dict

# def _get_log_extra() -> Dict[str, Any]:
#     """从上下文自动提取日志额外字段（核心：注入request_id/user_id）"""
#     ctx = get_request_context()
#     if not ctx:
#         return {
#             "request_id": "",
#             "user_id": "",
#             "http_method": "",
#             "path": "",
#             "client_ip": "",
#             "request_duration": 0.0,
#             "status_code": 0
#         }
    
#     # 计算请求耗时（毫秒）
#     duration = 0.0
#     if ctx.start_time:
#         duration = round((time.time() - ctx.start_time) * 1000, 2)
    
#     return {
#         "request_id": ctx.request_id,
#         "user_id": ctx.user_id or "anonymous",
#         "http_method": ctx.http_method or "",
#         "path": ctx.path or "",
#         "client_ip": ctx.client_ip or "",
#         "request_duration_ms": duration,
#         "status_code": ctx.status_code or 0,
#         "is_slow_request": duration > 500  # 标记慢请求（>500ms）
#     }

class SensitiveFilter:
    def __init__(self, sensitive_fields):
        self.sensitive_fields = set(sensitive_fields)
   
    def __call__(self, logger, method_name, event_dict):
        # 企业级：过滤请求体中的敏感字段
        if "request" in event_dict and "body" in event_dict["request"]:
            body = event_dict["request"]["body"]
            if isinstance(body, dict):
                for field in self.sensitive_fields:
                    if field in body:
                        body[field] = "[REDACTED]"        

        # 企业级：过滤响应体中的敏感字段
        if "response" in event_dict and "body" in event_dict["response"]:
            body = event_dict["response"]["body"]
            if isinstance(body, dict):
                for field in self.sensitive_fields:
                    if field in body:
                        body[field] = "[REDACTED]"        

        return event_dict
    
def configure_file_logger():
    # 开发环境：控制台彩色格式（显示文件名+行号+函数名）
    console_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{file.name}</cyan>:<cyan>{line}</cyan> (<cyan>{function}</cyan>) | "
        # "<magenta>{extra.get('request_id', '')}</magenta> | "
        # "<yellow>{extra.get('user_id', '')}</yellow> | "
        # "<blue>{extra.get('http_method', '')} {extra.get('path', '')}</blue> | "
        "<level>{message}</level>"
    )

    # 生产环境：JSON格式（修复非法格式符）
    json_format = {
        "time": "{time:YYYY-MM-DD HH:mm:ss.SSS}",
        "level": "{level}",
        "logger": "{name}",
        "filename": "{file.name}",
        "lineno": "{line}",
        "funcname": "{function}",
        # 修复：移除!s:-0，改用get获取默认值
        # "request_id": "{extra.get('request_id', '')}",
        # "user_id": "{extra.get('user_id', '')}",
        # "http_method": "{extra.get('http_method', '')}",
        # "path": "{extra.get('path', '')}",
        # "client_ip": "{extra.get('client_ip', '')}",
        # "request_duration_ms": "{extra.get('request_duration_ms', 0)}",
        # "status_code": "{extra.get('status_code', 0)}",
        # "is_slow_request": "{extra.get('is_slow_request', False)}",
        "message": "{message}",
        "exception": "{exception}"
    }
    """配置Loguru日志轮转（替代structlog文件输出，性能更高）"""
    loguru_logger.remove()

    # 创建日志目录
    loguru_logger.add(
        sink="logs/app-{time:YYYY-MM-DD}.err",
        level="ERROR" if settings.ENV == "dev" else "INFO",
        format=console_format if settings.ENV == "dev" else json_format,
        rotation="00:00",
        retention="90 days",
        compression="zip",
        encoding="utf-8",
        # format="json",
        # format="{message}",
        enqueue=True,  # 异步写入（无锁）
    )
    loguru_logger.add(
        sink="logs/app-{time:YYYY-MM-DD}.log",
        level="DEBUG" if settings.ENV == "dev" else "INFO",
        format=console_format if settings.ENV == "dev" else json_format,
        rotation="00:00",
        retention="90 days",
        compression="zip",
        encoding="utf-8",
        # format="json",
        # format="{message}",
        enqueue=True,  # 异步写入（无锁）
    )
    loguru_logger.add(sys.stdout, level="INFO", enqueue=True, format="{message}")


def setup_strcutlogger():
    # bind_contextvars(
    #     request_id="",  # 改为空字符串，避免占位符
    #     trace_id="",
    #     user_id="",
    #     session_id="",
    #     client_ip="",
    #     correlation_id="",
    #     endpoint=""
    # )

    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="%Y-%m-%dT%H:%M:%S.%fZ", key="timestamp"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            # structlog.stdlib.ProcessorFormatter.wrap_for_formatter, #（避免嵌套）
            # structlog.processors.KeyValueRenderer(key_order=["timestamp", "level", "event", "request_id", "user_id"]),
            SensitiveFilter(sensitive_fields=settings.AUDIT_LOG_SENSITIVE_FIELDS),
            # structlog.stdlib.filter_by_level,
            structlog_context_processor, # 注入上下文
            structlog.processors.JSONRenderer(),
            # structlog.dev.ConsoleRenderer(), # 设置后会报错
        ],
        # wrapper_class=structlog.make_filtering_bound_logger(logging.INFO)
        logger_factory=lambda name: loguru_logger.bind(name=name),
        wrapper_class=structlog.stdlib.BoundLogger,
        # 企业级：高性能配置
        cache_logger_on_first_use=True,
    )

    configure_file_logger()

    logger = structlog.get_logger(settings.APP_NAME)    
    # 企业级：设置日志级别（生产环境）
    # logger.setLevel(settings.LOG_LEVEL)

    if settings.AUDIT_LOG_ENABLED:
        return structlog.get_logger("AUDIT_LOG")        
    return structlog.get_logger()

class AsyncLogProcessor:
    """
    异步日志处理器（非阻塞+批量写入）
    核心优势：请求处理不阻塞日志IO，高并发下性能提升50%+
    """
    def __init__(self, batch_size: int = 100, flush_interval: int = 1):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.queue = queue.Queue(maxsize=10000)  # 日志队列（限长避免OOM）
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self.thread.start()

    def _run_async_loop(self):
        """启动异步循环（后台线程）"""
        asyncio.set_event_loop(self.loop)
        self.loop.create_task(self._process_batch())
        self.loop.run_forever()

    async def _process_batch(self):
        """批量处理日志（异步）"""
        batch = []
        last_flush = asyncio.get_event_loop().time()
        while True:
            try:
                # 从队列获取日志（非阻塞）
                while len(batch) < self.batch_size:
                    try:
                        log_entry = self.queue.get(block=False)
                        batch.append(log_entry)
                    except queue.Empty:
                        break
                # 批量写入
                if batch and (
                    len(batch) >= self.batch_size 
                    or asyncio.get_event_loop().time() - last_flush >= self.flush_interval
                ):
                    await self._write_batch(batch)
                    batch.clear()
                    last_flush = asyncio.get_event_loop().time()
                await asyncio.sleep(0.01)  # 避免空轮询
            except Exception as e:
                structlog.get_logger("async_logger").error("Async log batch failed", error=str(e))

    async def _write_batch(self, batch: list):
        """写入日志（适配stdout/文件）"""
        for entry in batch:
            # JSON格式直接输出，控制台格式美化
            if settings.LOG.FORMAT == "json":
                print(entry, flush=True)
            else:
                # 开发环境控制台输出
                print(f"[{entry['timestamp']}] [{entry['level']}] {entry['event']}", flush=True)
            # 生产环境文件日志（由Loguru处理）
            from loguru import logger
            logger.info(entry)

    def __call__(self, logger, method_name, event_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """structlog处理器入口（非阻塞入队）"""
        try:
            # 队列满时降级为同步输出（避免丢失）
            if self.queue.full():
                structlog.get_logger("async_logger").warning("Log queue full, falling back to sync")
                return event_dict
            # 异步入队
            self.queue.put(event_dict, block=False)
            return None  # 阻止后续同步处理器执行
        except Exception as e:
            structlog.get_logger("async_logger").error("Async log enqueue failed", error=str(e))
            return event_dict  # 降级为同步输出

logger = setup_strcutlogger()

# 审计日志专用 logger
# audit_logger = structlog.get_logger("AUDIT")

# async def exception_handler(request: Request, exc: Exception):
#     # 企业级：记录异常
#     logger.error(
#         "Unhandled exception",
#         event="unhandled_exception",
#         exception=str(exc),
#         traceback=exc.__traceback__,
#         request_id=request.state.request_id,
#         ip_address=request.client.host,
#         method=request.method,
#         path=request.url.path,
#     )
#     return JSONResponse(
#         status_code=500,
#         content={"detail": "Internal server error"},
#     )