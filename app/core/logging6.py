# -*- coding: utf-8 -*-

# app/logging.py - 企业级：高性能日志配置
import structlog
from structlog.processors import TimeStamper, StackInfoRenderer
from structlog.stdlib import LoggerFactory
from structlog.threadlocal import ThreadLocalsProcessor
from fastapi import Request
from fastapi_structlog import StructLogMiddleware

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

# 企业级：高性能日志配置
def init_logging():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            ThreadLocalsProcessor(),
            structlog.processors.add_log_level,
            structlog.processors.format_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.KeyValueRenderer(key_order=["timestamp", "level", "event", "request_id", "user_id"]),
            SensitiveFilter(sensitive_fields=["password", "token", "api_key"]),
        ],
        context_processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.add_log_level,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            structlog.get_logger().level
        ),
        logger_factory=LoggerFactory(),
        # 企业级：高性能配置
        cache_logger_on_first_use=True,
        # 企业级：避免日志阻塞
        async_rendering=False,
    )
    
    # 企业级：设置日志级别（生产环境）
    structlog.get_logger().setLevel(structlog.get_logger().level)    
    return structlog.get_logger()

################
# app/middleware.py - 企业级：异常处理
from fastapi import Request, HTTPException
from structlog import get_logger
logger = get_logger()
async def exception_handler(request: Request, exc: Exception):
    # 企业级：记录异常
    logger.error(
        "Unhandled exception",
        event="unhandled_exception",
        exception=str(exc),
        traceback=exc.__traceback__,
        request_id=request.state.request_id,
        ip_address=request.client.host,
        method=request.method,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )