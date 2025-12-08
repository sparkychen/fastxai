# -*- coding: utf-8 -*-

import time
from starlette.middleware.base import BaseHTTPMiddleware
from uuid_extensions import uuid7
from app.core.config import settings
from contextvars import ContextVar
from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
from app.core.audit_log import mask_sensitive_data
from typing import Callable, Optional, Dict, Any
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import re
from app.core.auth import auth_service
import structlog
from fastapi import Request, Response, HTTPException, FastAPI, status
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.sessions import SessionMiddleware
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

class SecurityHeadersConfig:
    """安全头部配置类"""    
    def __init__(self):
        self.hsts_max_age = 31536000  # 1年
        self.csp_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        self.referrer_policy = "strict-origin-when-cross-origin"
    
    def get_headers(self) -> dict:
        return {
            "Strict-Transport-Security": f"max-age={self.hsts_max_age}; includeSubDomains",
            "Content-Security-Policy": self.csp_policy,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": self.referrer_policy,
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-cache, no-store, must-revalidate"
        }


# 1. 定义安全头配置（可抽离到配置文件）
SECURITY_HEADERS: Dict[str, str] = {
    # 核心安全头（企业级必配）
    "X-Frame-Options": "DENY",  # 防止点击劫持
    "X-XSS-Protection": "1; mode=block",  # 开启 XSS 过滤
    "X-Content-Type-Options": "nosniff",  # 禁止 MIME 类型嗅探
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",  # HSTS（强制 HTTPS）
    "Referrer-Policy": "strict-origin-when-cross-origin",  # 控制 Referrer 发送
    "Cache-Control": "no-store, max-age=0",  # 禁止缓存敏感数据
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'",  # CSP（按需调整）
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",  # 禁用敏感权限
}

# 2. 自定义安全头中间件
class SecurityHeadersMiddleware:
    def __init__(self, app, headers: Dict[str, str] = None):
        self.app = app
        self.headers = headers or SECURITY_HEADERS

    async def __call__(self, request: Request, call_next):
        # 处理请求，获取响应
        response: Response = await call_next(request)
        # 为响应添加所有安全头
        for header, value in self.headers.items():
            response.headers[header] = value
        return response
    
# 初始化速率限制器
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.API_RATE_LIMIT]
)



class SecurityMiddleware:
    """安全中间件集合"""

    def __init__(self, app, config: SecurityHeadersConfig = None):
        self.app = app
        self.config = config or SecurityHeadersConfig()
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # 创建自定义send函数来拦截响应
            original_send = send
            
            async def send_with_headers(message):
                if message["type"] == "http.response.start":
                    # 添加安全头部
                    headers = dict(message.get("headers", []))
                    security_headers = self.config.get_headers()
                    
                    for header, value in security_headers.items():
                        headers[header.encode()] = value.encode()
                    
                    message["headers"] = list(headers.items())
                
                await original_send(message)
            
            await self.app(scope, receive, send_with_headers)
        else:
            await self.app(scope, receive, send)
    
    @staticmethod
    def setup_security_middleware(app: FastAPI):
        """设置所有安全中间件"""
        
        # 1. 速率限制
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)
        
        # 2. CORS配置
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            allow_headers=["*"],
            expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
            max_age=600,
        )
        
        # 3. 可信主机
        if settings.TRUSTED_HOSTS:
            app.add_middleware(
                TrustedHostMiddleware,
                allowed_hosts=settings.TRUSTED_HOSTS,
            )
        
        # 4. GZIP压缩
        app.add_middleware(GZipMiddleware, minimum_size=1000)
        
        # 5. 自定义安全中间件
        @app.middleware("http")
        async def add_security_headers(request: Request, call_next: Callable):
            """添加安全头"""
            start_time = time.time()
            
            # 生成请求ID
            request_id = request.headers.get("X-Request-ID") or str(uuid7())
            
            # 添加请求ID到请求状态
            request.state.request_id = request_id
            
            # IP检查和限制
            client_ip = request.client.host if request.client else "0.0.0.0"
            
            # 检查IP黑名单
            if client_ip in settings.IP_BLACKLIST:
                logger.warning("IP blocked", ip=client_ip, path=request.url.path)
                return Response(
                    content="Access denied",
                    status_code=status.HTTP_403_FORBIDDEN,
                    headers={"X-Request-ID": request_id}
                )
            
            # 检查IP白名单（如果设置了）
            if (settings.IP_WHITELIST and 
                client_ip not in settings.IP_WHITELIST):
                logger.warning("IP not in whitelist", ip=client_ip, path=request.url.path)
                return Response(
                    content="Access denied",
                    status_code=status.HTTP_403_FORBIDDEN,
                    headers={"X-Request-ID": request_id}
                )
            
            try:
                # 处理请求
                response = await call_next(request)
                
                # 计算处理时间
                process_time = time.time() - start_time
                
                # 添加安全头
                for header, value in settings.SECURITY_HEADERS.items():
                    response.headers[header] = value
                
                # 添加自定义头
                response.headers["X-Request-ID"] = request_id
                response.headers["X-Process-Time"] = str(process_time)
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                response.headers["X-XSS-Protection"] = "1; mode=block"
                
                # 记录访问日志
                logger.info(
                    "Request processed",
                    request_id=request_id,
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    process_time=process_time,
                    client_ip=client_ip,
                    user_agent=request.headers.get("user-agent"),
                )
                
                return response
                
            except Exception as e:
                # 记录错误
                logger.error(
                    "Request error",
                    request_id=request_id,
                    error=str(e),
                    client_ip=client_ip,
                    path=request.url.path,
                )
                raise
        
        @app.middleware("http")
        async def sql_injection_protection(request: Request, call_next: Callable):
            """SQL注入防护"""
            # 检查URL参数
            for param in request.query_params.values():
                if SecurityMiddleware._detect_sql_injection(param):
                    logger.warning(
                        "SQL injection attempt detected",
                        ip=request.client.host,
                        param=param[:50],  # 只记录前50个字符
                        path=request.url.path,
                    )
                    return Response(
                        content="Invalid request",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )
            
            # 对于POST请求，检查表单数据
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if "application/x-www-form-urlencoded" in content_type:
                    try:
                        form_data = await request.form()
                        for value in form_data.values():
                            if SecurityMiddleware._detect_sql_injection(str(value)):
                                logger.warning(
                                    "SQL injection attempt in form data",
                                    ip=request.client.host,
                                    path=request.url.path,
                                )
                                return Response(
                                    content="Invalid request",
                                    status_code=status.HTTP_400_BAD_REQUEST,
                                )
                    except Exception:
                        pass
            
            return await call_next(request)
        
        @app.middleware("http")
        async def xss_protection(request: Request, call_next: Callable):
            """XSS防护"""
            response = await call_next(request)
            
            # 对于JSON响应，确保Content-Type正确
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                response.headers["Content-Type"] = "application/json; charset=utf-8"
            
            return response
    
    @staticmethod
    def _detect_sql_injection(input_str: str) -> bool:
        """检测SQL注入尝试"""
        if not input_str:
            return False
        
        # SQL注入模式检测
        sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # 单引号、注释
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # = 后跟SQL
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # 'or'
            r"((\%27)|(\'))union",  # 'union
            r"((\%27)|(\'))select",  # 'select
            r"((\%27)|(\'))insert",  # 'insert
            r"((\%27)|(\'))update",  # 'update
            r"((\%27)|(\'))delete",  # 'delete
            r"((\%27)|(\'))drop",  # 'drop
            r"((\%27)|(\'))exec",  # 'exec
            r"((\%27)|(\'))execute",  # 'execute
            r"((\%27)|(\'))truncate",  # 'truncate
            r"((\%27)|(\'))alter",  # 'alter
            r"((\%27)|(\'))create",  # 'create
            r"((\%27)|(\'))grant",  # 'grant
            r"((\%27)|(\'))revoke",  # 'revoke
            r"((\%27)|(\'))declare",  # 'declare
            r"((\%27)|(\'))shutdown",  # 'shutdown
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        
        return False

class RateLimitMiddleware:
    """增强的速率限制中间件"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # 基于用户ID的速率限制
        user_id = "anonymous"
        try:
            # 尝试从JWT令牌中获取用户ID
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
                payload = auth_service.decode_token(token)
                user_id = payload.get("sub", "anonymous")
        except Exception:
            pass
        
        # 使用用户ID作为速率限制键
        request.scope["rate_limit_key"] = user_id
        
        await self.app(scope, receive, send)


# ================= 1. 请求ID中间件 =================
class RequestIdMiddleware(BaseHTTPMiddleware):
    """为每个请求生成唯一ID，便于追踪"""
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid7()))
        structlog.contextvars.bind_contextvars(request_id=request_id)
        request.state.request_id = request_id
        
        # 记录请求开始
        start_time = time.time()
        logger.info(
            "Request started",
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host,
            user_agent=request.headers.get("User-Agent", "")
        )
        
        # 处理请求
        response = await call_next(request)
        
        # 记录请求结束
        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        logger.info(
            "Request completed",
            status_code=response.status_code,
            process_time=f"{process_time:.4f}s"
        )
        
        structlog.contextvars.clear_contextvars()
        return response

# ================= 2. 安全头部中间件 =================
def get_security_headers_config() -> SecurityHeadersConfig:
    """安全头部配置（防XSS/点击劫持等）"""
    return SecurityHeadersConfig(
        # 基础头部
        x_content_type_options="nosniff",
        x_frame_options="DENY",  # 防点击劫持
        x_xss_protection="1; mode=block",
        referrer_policy="strict-origin-when-cross-origin",
        # CSP（内容安全策略）
        content_security_policy=settings.CONTENT_SECURITY_POLICY,
        # HSTS（强制HTTPS）
        strict_transport_security="max-age=31536000; includeSubDomains; preload" if settings.is_production else "",
        # 其他
        permissions_policy="camera=(), microphone=(), geolocation=()",
        cache_control="no-store, max-age=0" if settings.is_production else "",
    )

# ================= 3. 审计日志中间件 =================
class AuditLogMiddleware(BaseHTTPMiddleware):
    """审计日志中间件（记录敏感操作）"""
    async def dispatch(self, request: Request, call_next):
        # 只记录敏感操作
        sensitive_paths = ["/auth", "/admin", "/api/v1/users", "/api/v1/settings"]
        if any(request.url.path.startswith(path) for path in sensitive_paths):
            # 获取用户信息（如果已认证）
            user_id = None
            try:
                from app.core.auth import get_current_user
                user = await get_current_user(request)
                user_id = str(user.id) if user else None
            except:
                pass
            
            # 记录审计日志
            logger.info(
                "Audit log",
                action=f"{request.method} {request.url.path}",
                user_id=user_id,
                client_ip=request.client.host,
                request_body=await request.body() if request.method in ["POST", "PUT", "PATCH"] else b""
            )
        
        return await call_next(request)

# ================= 4. 全局中间件配置 =================
def setup_security_middlewares(app: FastAPI):
    """配置所有安全中间件"""
    # 生产环境强制HTTPS
    if settings.is_production:
        app.add_middleware(HTTPSRedirectMiddleware)
    
    # 可信主机（防止主机头攻击）
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
    
    # CORS（严格配置）
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
    )
    
    # 请求ID
    app.add_middleware(RequestIdMiddleware)
    
    # 安全头部
    if settings.SECURITY_HEADERS_ENABLED:
        app.add_middleware(
            SecurityHeadersMiddleware,
            config=get_security_headers_config(),
            headers=SECURITY_HEADERS,
        )
    
    # 审计日志
    if settings.AUDIT_LOG_ENABLED:
        app.add_middleware(AuditLogMiddleware)
    
    # GZip压缩（提升性能）
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # 会话中间件（用于CSRF）
    app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
    
    logger.info("Security middlewares configured")


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
        request_id = str(uuid7())
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
                logger.warning("Request object not found for audit log")
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