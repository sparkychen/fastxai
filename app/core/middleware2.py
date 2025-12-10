# -*- coding: utf-8 -*-

import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp
from app.core.context import (
    RequestContext,
    set_request_context,
    clear_request_context,
    generate_request_id
)
from app.core.logger import logger, bind_contextvars, clear_contextvars

class EnterpriseRequestContextMiddleware(BaseHTTPMiddleware):
    """企业级请求上下文中间件（高性能、异步安全）"""
    def __init__(
        self,
        app: ASGIApp,
        request_id_header: str = "X-Request-ID",
        user_id_header: str = "X-User-ID",
        skip_paths: list = None  # 跳过健康检查等路径
    ):
        super().__init__(app)
        self.request_id_header = request_id_header
        self.user_id_header = user_id_header
        self.skip_paths = skip_paths or ["/health", "/metrics"]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """核心调度逻辑（异步、无阻塞）"""
        # 跳过指定路径（性能优化）
        if request.url.path in self.skip_paths:
            bind_contextvars(
                request_id="",
                user_id="",
                client_ip="",
                endpoint=request.url.path,
                http_method=request.method,
            )
            # 初始化空上下文（仅用于日志，无实际数据）
            empty_ctx = RequestContext(request_id="", user_id="")
            set_request_context(empty_ctx)
            try:
                return await call_next(request)
            finally:
                clear_request_context()  # 清理上下文
                clear_contextvars() 
            return await call_next(request)

        # 1. 初始化请求上下文
        start_time = time.time()
        request_id = request.headers.get(self.request_id_header) or generate_request_id()
        user_id = request.headers.get(self.user_id_header) or "anonymous"
        if "X-Forwarded-For" in request.headers:
            client_ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
        else:                  
            # 获取客户端IP（企业级规范：支持反向代理）
            client_ip = request.client.host

        # 2. 绑定上下文（协程安全）
        ctx = RequestContext(
            request_id=request_id,
            user_id=user_id,
            http_method=request.method,
            path=request.url.path,
            client_ip=client_ip,
            start_time=start_time
        )
        set_request_context(ctx)
        # 核心：同步到structlog的contextvars
        bind_contextvars(
            request_id=request_id,
            user_id=user_id,
            client_ip=client_ip,
            endpoint=request.url.path,
            http_method=request.method,
            # trace_idd="",  # 若有链路追踪，此处赋值
            # correlation_id="",
            correlation_id=request_id,  # 关联ID=请求ID
            correlattion_id=request_id, # 兼容拼写错误
            trace_id=request_id,
            trace_idd=request_id,
            session_id=request.cookies.get("session_id", ""),
        )
        

        # 3. 记录请求开始日志（企业级审计）
        logger.info(
            "Request started",
            client_user_agent=request.headers.get("User-Agent", ""),
            content_length=request.headers.get("Content-Length", 0)
        )

        response: Response = None
        try:
            # 4. 处理请求（无阻塞）
            response = await call_next(request)
            ctx.status_code = response.status_code
            set_request_context(ctx)  # 更新状态码

            # 5. 记录请求完成日志
            logger.info(
                "Request completed",
                status_code=response.status_code,
                response_content_length=response.headers.get("Content-Length", 0)
            )
            bind_contextvars(status_code=response.status_code)
            return response
        except Exception as e:
            # 6. 异常处理（企业级故障排查）
            ctx.status_code = 500
            set_request_context(ctx)
            bind_contextvars(status_code=500, exception=str(e))
            logger.error(
                "Request failed",
                exception=str(e),
                exc_info=True  # 记录完整异常栈
            )
            raise
        finally:
            # 7. 清理上下文（避免内存泄漏）
            clear_request_context()
            clear_contextvars()

class SlowRequestMiddleware(BaseHTTPMiddleware):
    """慢请求标记中间件（企业级性能监控）"""
    def __init__(self, app: ASGIApp, slow_threshold_ms: int = 500):
        super().__init__(app)
        self.slow_threshold_ms = slow_threshold_ms

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.time()
        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000
        
        if duration_ms > self.slow_threshold_ms:
            logger.warning(
                "Slow request detected",
                request_duration_ms=round(duration_ms, 2),
                threshold_ms=self.slow_threshold_ms
            )
        return response
