# -*- coding: utf-8 -*-

from fastapi import Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi_security_headers import SecurityHeadersMiddleware, SecurityHeadersConfig
import uuid
import time
import structlog
from app.security.sc_config import security_settings

logger = structlog.get_logger()

# ================= 1. 请求ID中间件 =================
class RequestIdMiddleware(BaseHTTPMiddleware):
    """为每个请求生成唯一ID，便于追踪"""
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
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
        content_security_policy=security_settings.CONTENT_SECURITY_POLICY,
        # HSTS（强制HTTPS）
        strict_transport_security="max-age=31536000; includeSubDomains; preload" if security_settings.is_production else "",
        # 其他
        permissions_policy="camera=(), microphone=(), geolocation=()",
        cache_control="no-store, max-age=0" if security_settings.is_production else "",
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
                from app.security.auth import get_current_user
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
    if security_settings.is_production:
        app.add_middleware(HTTPSRedirectMiddleware)
    
    # 可信主机（防止主机头攻击）
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=security_settings.ALLOWED_HOSTS)
    
    # CORS（严格配置）
    app.add_middleware(
        CORSMiddleware,
        allow_origins=security_settings.CORS_ORIGINS,
        allow_credentials=security_settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=security_settings.CORS_ALLOW_METHODS,
        allow_headers=security_settings.CORS_ALLOW_HEADERS,
    )
    
    # 请求ID
    app.add_middleware(RequestIdMiddleware)
    
    # 安全头部
    if security_settings.SECURITY_HEADERS_ENABLED:
        app.add_middleware(
            SecurityHeadersMiddleware,
            config=get_security_headers_config()
        )
    
    # 审计日志
    if security_settings.AUDIT_LOG_ENABLED:
        app.add_middleware(AuditLogMiddleware)
    
    # GZip压缩（提升性能）
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # 会话中间件（用于CSRF）
    app.add_middleware(SessionMiddleware, secret_key=security_settings.SECRET_KEY)
    
    logger.info("Security middlewares configured")
