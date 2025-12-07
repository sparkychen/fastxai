# -*- coding: utf-8 -*-

from fastapi import Request, HTTPException, FastAPI
from fastapi.responses import ORJSONResponse
import sentry_sdk
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

async def http_exception_handler(request: Request, exc: HTTPException):
    """结构化HTTP异常日志"""
    logger.error(
        "HTTP exception",
        status_code=exc.status_code,
        detail=exc.detail,
        endpoint=f"{request.method} {request.url.path}",
        exc_info=True,
    )
    return ORJSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "request_id": request.state.get("request_id", ""),
            "trace_id": request.state.get("trace_id", ""),
        },
    )

async def generic_exception_handler(request: Request, exc: Exception):
    """通用异常日志（捕获所有未处理异常）"""
    logger.critical(
        "Unhandled exception",
        endpoint=f"{request.method} {request.url.path}",
        exc_info=True,  # 记录完整异常栈
        client_ip=request.client.host,
    )
    return ORJSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": request.state.get("request_id", ""),
            "trace_id": request.state.get("trace_id", ""),
        },
    )

async def sentry_exception_handler(request: Request, exc: Exception) -> ORJSONResponse:
    """全局异常处理器"""    
    # 设置请求上下文
    with sentry_sdk.configure_scope() as scope:
        scope.set_context("request", {
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "query_params": dict(request.query_params),
        })
        
        # 对于 HTTP 异常，使用 warning 级别
        if isinstance(exc, HTTPException):
            sentry_sdk.capture_message(
                f"HTTP {exc.status_code}: {exc.detail}",
                level="warning"
            )
        else:
            # 其他异常使用 error 级别
            sentry_sdk.capture_exception(exc)
    
    # 返回标准化错误响应
    if isinstance(exc, HTTPException):
        return ORJSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "request_id": request.headers.get("X-Request-ID", "unknown")
                }
            }
        )
    else:
        return ORJSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": 500,
                    "message": "Internal Server Error",
                    "request_id": request.headers.get("X-Request-ID", "unknown")
                }
            }
        )

def setup_exception_handlers(app: FastAPI):
    """设置异常处理器"""
    app.add_exception_handler(Exception, sentry_exception_handler)
