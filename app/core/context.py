# -*- coding: utf-8 -*-

import contextvars
from dataclasses import dataclass
from typing import Optional
from uuid_extensions import uuid7
from contextvars import ContextVar

# 定义上下文变量（协程局部，异步安全）
_request_context: contextvars.ContextVar[Optional["RequestContext"]] = contextvars.ContextVar(
    "request_context", default=None
)

@dataclass
class RequestContext:
    """企业级请求上下文模型（可扩展）"""
    request_id: str = ""
    user_id: str = ""
    http_method: str = ""
    path: Optional[str] = None
    client_ip: Optional[str] = None
    start_time: Optional[float] = None  # 请求开始时间（用于计算耗时）
    status_code: Optional[int] = None   # 响应状态码

_request_context_var: ContextVar[RequestContext] = ContextVar(
    "request_context", 
    default=RequestContext(request_id="")  # 默认空request_id
)

def get_request_context() -> Optional[RequestContext]:
    """获取当前请求上下文"""
    return _request_context_var.get()

def set_request_context(ctx: RequestContext) -> None:
    """设置当前请求上下文"""
    _request_context_var.set(ctx)

def generate_request_id() -> str:
    """生成唯一Request ID（符合RFC 4122）"""
    return str(uuid7())

def clear_request_context() -> None:
    """清理请求上下文（避免内存泄漏）"""
    _request_context_var.set(RequestContext(request_id=""))
