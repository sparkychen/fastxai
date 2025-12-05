# app/middleware/logging.py
import uuid
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logger import logger, bind_context, unbind_context
from app.core.config import settings

class RequestContextLoggingMiddleware(BaseHTTPMiddleware):
    """
    请求上下文日志中间件（企业级）
    核心能力：
    1. 生成唯一request_id
    2. 绑定trace_id/span_id（分布式追踪）
    3. 记录请求耗时/状态码/端点
    4. 绑定用户ID/租户ID（认证后）
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        # ========== 1. 初始化请求上下文 ==========
        request_id = str(uuid.uuid4())
        start_time = time.time()
        # 绑定基础上下文
        bind_context(
            request_id=request_id,
            endpoint=f"{request.method} {request.url.path}",
            client_ip=request.client.host,
            user_agent=request.headers.get("User-Agent", "unknown"),
        )
        # 绑定分布式追踪ID（由tracing中间件生成）
        trace_id = request.state.get("trace_id", "")
        span_id = request.state.get("span_id", "")
        bind_context(trace_id=trace_id, span_id=span_id)

        # ========== 2. 处理请求 ==========
        try:
            response = await call_next(request)
            status_code = response.status_code
            # 认证后绑定用户/租户ID（需配合FastAPI-Users）
            if hasattr(request.state, "user"):
                bind_context(
                    user_id=str(request.state.user.id),
                    tenant_id=str(request.state.user.tenant_id)
                )
        except Exception as e:
            # 异常处理（结构化异常日志）
            status_code = 500
            logger.error(
                "Request failed",
                error=str(e),
                exc_info=True,  # 记录异常栈
            )
            raise
        finally:
            # ========== 3. 记录请求日志（性能+合规） ==========
            duration = round((time.time() - start_time) * 1000, 2)  # 耗时（毫秒）
            logger.info(
                "Request processed",
                status_code=status_code,
                duration=f"{duration}ms",
                path=request.url.path,
                method=request.method,
            )
            # ========== 4. 清理上下文（避免内存泄漏） ==========
            unbind_context()

        # ========== 5. 返回响应（携带request_id） ==========
        response.headers["X-Request-ID"] = request_id
        return response
