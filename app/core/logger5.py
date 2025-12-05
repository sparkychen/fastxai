# -*- coding: utf-8 -*-


# app/middleware/logging.py  结构化日志中间件
import time
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.auth import observe_response_time

logger = structlog.get_logger("middleware")

class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # 请求开始时间
        start_time = time.time()
        # 基础日志信息
        log_data = {
            "method": request.method,
            "path": request.url.path,
            "client_ip": request.client.host,
            "user_agent": request.headers.get("User-Agent", "unknown")
        }
        try:
            # 处理请求
            response = await call_next(request)
            # 响应信息
            log_data["status_code"] = response.status_code
            log_data["duration_seconds"] = round(time.time() - start_time, 4)
            # 记录响应时间指标
            observe_response_time(request.url.path, log_data["duration_seconds"])
            # 日志级别（成功/失败）
            if response.status_code >= 400:
                logger.warning("request_failed", **log_data)
            else:
                logger.info("request_succeeded", **log_data)
            return response
        except Exception as e:
            log_data["status_code"] = 500
            log_data["error"] = str(e)
            log_data["duration_seconds"] = round(time.time() - start_time, 4)
            logger.error("request_error", **log_data)
            raise
