# -*- coding: utf-8 -*-

import time
import structlog
from typing import Optional, Dict, Any
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import uuid
import time
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logger import audit_logger
from app.core.config import settings
from contextvars import ContextVar
from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
from app.core.audit_log import mask_sensitive_data

logger = structlog.get_logger("middleware")


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
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
        bind_contextvars(
            request_id=request_id,
            endpoint=f"{request.method} {request.url.path}",
            client_ip=request.client.host,
            user_agent=request.headers.get("User-Agent", "unknown"),
        )
        # 绑定分布式追踪ID（由tracing中间件生成）
        trace_id = request.state.get("trace_id", "")
        span_id = request.state.get("span_id", "")
        bind_contextvars(trace_id=trace_id, span_id=span_id)

        # ========== 2. 处理请求 ==========
        try:
            response = await call_next(request)
            status_code = response.status_code
            # 认证后绑定用户/租户ID（需配合FastAPI-Users）
            if hasattr(request.state, "user"):
                bind_contextvars(
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
            clear_contextvars()

        # ========== 5. 返回响应（携带request_id） ==========
        response.headers["X-Request-ID"] = request_id
        return response
    
# ========== 审计日志中间件 ==========
class AuditLogMiddleware(BaseHTTPMiddleware):
    """自动记录请求全生命周期审计日志"""
    async def dispatch(self, request: Request, call_next) -> Response:
        # 忽略指定路径
        if request.url.path in settings.AUDIT_LOG_IGNORE_PATHS:
            return await call_next(request)
        
        # 初始化审计日志基础数据
        audit_data: Dict[str, Any] = {
            "request_ip": self._get_client_ip(request),
            "request_method": request.method,
            "request_path": request.url.path,
            "request_params": dict(request.query_params),
            "timestamp": time.time(),
            "status": "success",
        }

        # 记录请求开始时间
        start_time = time.time()
        response: Optional[Response] = None
        error_msg: Optional[str] = None

        try:
            # 获取当前用户（需根据实际认证逻辑调整）
            await self._get_current_user(request, audit_data)
            
            # 读取请求体（脱敏）
            if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
                try:
                    body = await request.json()
                    audit_data["request_body"] = mask_sensitive_data(body)
                except Exception:
                    # 非JSON请求体（如表单）
                    audit_data["request_body"] = "non-json body"
            # 处理请求
            response = await call_next(request)
            audit_data["response_status"] = response.status_code
        except HTTPException as e:
            # 捕获HTTP异常
            response = Response(
                content=e.detail,
                status_code=e.status_code,
                headers=e.headers
            )
            audit_data["response_status"] = e.status_code
            audit_data["status"] = "failed"
            audit_data["error_msg"] = str(e.detail)
        except Exception as e:
            # 捕获未知异常
            response = Response(
                content="Internal server error",
                status_code=500
            )
            audit_data["response_status"] = 500
            audit_data["status"] = "failed"
            audit_data["error_msg"] = str(e)
            raise
        finally:
            # 补充响应时间
            audit_data["response_time"] = time.time() - start_time            
            # 补充操作类型（默认）
            audit_data.setdefault("operation", f"{request.method.lower()}_resource")
            audit_data.setdefault("resource_type", "unknown")
            audit_data.setdefault("resource_id", None)            
            # 写入审计日志（异步无阻塞）
            await audit_log_service.write_audit_log(audit_data)
        return response

    def _get_client_ip(self, request: Request) -> str:
        """获取真实客户端IP（支持反向代理）"""
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def _get_current_user(self, request: Request, audit_data: Dict[str, Any]):
        """获取当前用户信息（需适配实际认证逻辑）"""
        try:
            # 示例：从JWT令牌获取用户信息
            from app.core.auth import get_current_user
            user = await get_current_user(request)
            audit_data["user_id"] = str(user.id)
            audit_data["user_name"] = user.username
        except Exception:
            # 匿名用户
            audit_data["user_id"] = "anonymous"
            audit_data["user_name"] = "anonymous"

# ========== 手动审计日志装饰器 ==========
def audit_log(operation: str, resource_type: str):
    """
    手动记录业务审计日志装饰器
    :param operation: 操作类型（如create_user、delete_order）
    :param resource_type: 资源类型（如user、order）
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # 获取请求对象（需保证第一个参数是request）
            request = args[0] if isinstance(args[0], Request) else None
            if not request:
                audit_logger.warning("Request object not found for audit log")
                return await func(*args, **kwargs)
            
            # 初始化审计数据
            audit_data = {
                "request_ip": AuditLogMiddleware._get_client_ip(request),
                "request_method": request.method,
                "request_path": request.url.path,
                "request_params": dict(request.query_params),
                "timestamp": time.time(),
                "operation": operation,
                "resource_type": resource_type,
                "status": "success",
            }

            # 获取用户信息
            await AuditLogMiddleware._get_current_user(None, request, audit_data)

            try:
                # 执行业务函数
                result = await func(*args, **kwargs)
                
                # 提取资源ID（示例：从返回结果或参数获取）
                resource_id = kwargs.get("resource_id") or (result.id if hasattr(result, "id") else None)
                audit_data["resource_id"] = str(resource_id) if resource_id else None
                
                return result
            except Exception as e:
                audit_data["status"] = "failed"
                audit_data["error_msg"] = str(e)
                raise
            finally:
                # 写入审计日志
                await audit_log_service.write_audit_log(audit_data)
        return wrapper
    return decorator