# -*- coding: utf-8 -*-

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import sentry_sdk
from contextvars import ContextVar
from typing import Dict, Any
from uuid_extensions import uuid7
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

# 上下文变量用于请求追踪
current_request_id: ContextVar[str] = ContextVar("request_id", default="")

class SentryPerformanceMiddleware(BaseHTTPMiddleware):
    """Sentry 性能监控中间件"""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # 生成请求ID
        request_id = str(uuid7())
        current_request_id.set(request_id)
        
        # 开始性能监控
        start_time = time.time()
        
        with sentry_sdk.start_span(op="http.server", name=f"{request.method} {request.url.path}") as span:
            # 设置事务上下文
            span.set_data("http.method", request.method)
            span.set_data("http.url", str(request.url))
            span.set_tag("request_id", request_id)
            
            try:
                # 设置用户上下文（如果有认证）
                await self._set_user_context(request)
                
                # 执行请求
                response = await call_next(request)
                
                # 记录性能数据
                duration = time.time() - start_time
                span.set_data("http.response_time", duration)
                span.set_tag("http.status_code", response.status_code)
                
                # 添加响应头
                response.headers["X-Request-ID"] = request_id
                response.headers["X-Response-Time"] = str(round(duration * 1000))
                
                return response
                
            except Exception as e:
                # 记录异常
                duration = time.time() - start_time
                span.set_tag("http.status_code", 500)
                span.set_data("error", str(e))
                
                # 捕获并上报异常
                with sentry_sdk.configure_scope() as scope:
                    scope.set_context("request", self._get_request_context(request))
                    scope.set_tag("request_id", request_id)
                    sentry_sdk.capture_exception(e)
                
                raise
    
    async def _set_user_context(self, request: Request):
        """设置用户上下文"""
        # 从请求中提取用户信息（根据你的认证系统调整）
        user_id = request.headers.get("X-User-ID")
        if user_id:
            sentry_sdk.set_user({"id": user_id, "ip_address": request.client.host})
    
    def _get_request_context(self, request: Request) -> Dict[str, Any]:
        """获取请求上下文信息"""
        return {
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "query_params": dict(request.query_params),
            "client_ip": request.client.host if request.client else None,
        }