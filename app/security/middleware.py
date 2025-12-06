# -*- coding: utf-8 -*-

import time
import uuid
from typing import Callable, Optional
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import structlog
import re
from app.core.config import settings
from .auth import auth_service

logger = structlog.get_logger()

# 初始化速率限制器
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.API_RATE_LIMIT]
)

class SecurityMiddleware:
    """安全中间件集合"""
    
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
            request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
            
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