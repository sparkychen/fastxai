# -*- coding: utf-8 -*-

from fastapi import Request, HTTPException
from fastapi.responses import ORJSONResponse
from app.core.logger import logger

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
