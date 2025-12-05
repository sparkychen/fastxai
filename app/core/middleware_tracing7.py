# app/middleware/tracing.py
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from app.core.config import settings

# 初始化OpenTelemetry追踪器
if settings.TRACING_ENABLE:
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(settings.TRACING_SERVICE_NAME)
    # 生产环境替换为OTLP exporter（对接Jaeger/Prometheus）
    trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
else:
    tracer = None

class TracingMiddleware(BaseHTTPMiddleware):
    """分布式追踪中间件（绑定trace_id/span_id到日志）"""
    async def dispatch(self, request: Request, call_next):
        if not tracer:
            return await call_next(request)
        # 创建span
        with tracer.start_as_current_span(f"{request.method} {request.url.path}") as span:
            # 获取trace_id/span_id（16进制字符串）
            trace_id = format(span.get_span_context().trace_id, "016x")
            span_id = format(span.get_span_context().span_id, "016x")
            # 绑定到request.state（供日志中间件使用）
            request.state.trace_id = trace_id
            request.state.span_id = span_id
            # 处理请求
            response = await call_next(request)
            # 设置span属性
            span.set_attribute("http.status_code", response.status_code)
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.path", request.url.path)
            return response
